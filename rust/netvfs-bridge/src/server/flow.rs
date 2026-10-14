// SPDX-License-Identifier: LGPL-2.1-or-later
//! The outgoing side of a session: one FIFO ([`Outbox`]) for every reply and
//! signal, written by a single writer task, and the byte budget of streamed
//! signals (C-10, design §3.4).
//!
//! zbus 5's `Connection::send` resolves only once the message is in the
//! kernel (design §8), so a consumer that stops reading leaves the writer
//! pending. Producers of `ListBatch` and `WalkBatch` acquire their bytes from
//! the session's [`FlowBudget`] before they enqueue; the writer releases
//! them after the send. A session therefore holds at most
//! [`FLOW_LIMIT`] bytes of pending batches (plus one batch and the
//! message being written), however slowly its consumer reads.
//!
//! Replies and other signals are not budgeted, but the session stops reading
//! calls while [`MAX_QUEUED`] messages wait to be written: a consumer that
//! sends calls without reading the replies is throttled by its own socket.

use super::SessionId;
use super::encode::OutSignal;
use netvfs_bridge_proto::limits::FLOW_LIMIT;
use std::fmt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use zbus::Message;

/// How often a waiting producer looks at its cancel flag.
const POLL: Duration = Duration::from_millis(20);
/// Messages waiting for the writer above which the session reads no calls.
pub const MAX_QUEUED: usize = 64;

/// Bytes of streamed signals that are enqueued but not yet written to the
/// socket (one per session). Shared with worker threads: `acquire` blocks.
#[derive(Debug)]
pub struct FlowBudget {
    limit: usize,
    state: Mutex<FlowState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct FlowState {
    in_flight: usize,
    closed: bool,
}

impl FlowBudget {
    /// A budget that lets producers in while at most `limit` bytes are in
    /// flight.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self { limit, state: Mutex::new(FlowState::default()), changed: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, FlowState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until at most the limit is in flight, then adds `bytes`. Blocks
    /// the calling thread (never call it on the runtime): wakes on every
    /// release and looks at `cancel` every 20 ms. False when canceled or
    /// when the session is gone; nothing is added then.
    pub fn acquire(&self, bytes: usize, cancel: &AtomicBool) -> bool {
        let mut state = self.lock();
        loop {
            if state.closed || cancel.load(Ordering::Acquire) {
                return false;
            }
            if state.in_flight <= self.limit {
                state.in_flight = state.in_flight.saturating_add(bytes);
                return true;
            }
            state = self.changed.wait_timeout(state, POLL).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Gives back `bytes` once they were written (or dropped).
    pub fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let mut state = self.lock();
        state.in_flight = state.in_flight.saturating_sub(bytes);
        drop(state);
        self.changed.notify_all();
    }

    /// The session is gone: every waiting and later `acquire` fails.
    pub fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// Bytes in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.lock().in_flight
    }

    /// Whether [`FlowBudget::close`] was called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }
}

/// One message for the writer.
#[derive(Debug)]
pub(crate) struct Outgoing {
    pub(super) message: Message,
    pub(super) flow_bytes: usize,
}

/// The connection of a session as the outbox and its writer see it: the
/// socket's shutdown handle (a duplicate of the descriptor zbus owns), the
/// closed flag and the number of queued messages.
#[derive(Debug)]
pub(crate) struct Link {
    socket: UnixStream,
    closed: watch::Sender<bool>,
    queued: watch::Sender<usize>,
}

impl Link {
    pub(crate) fn new(socket: UnixStream) -> Self {
        Self { socket, closed: watch::Sender::new(false), queued: watch::Sender::new(0) }
    }

    /// Shuts the socket down: zbus's reads and writes on it fail at once,
    /// also a send that waits for a consumer that does not read.
    pub(crate) fn close(&self) {
        if !self.closed.send_replace(true) {
            // An error only means the peer is gone already.
            drop(self.socket.shutdown(std::net::Shutdown::Both));
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    pub(crate) async fn wait_closed(&self) {
        let mut rx = self.closed.subscribe();
        // An error means the sender is gone, which cannot happen while
        // `self` lives; the guard is released at once.
        drop(rx.wait_for(|closed| *closed).await);
    }

    /// Waits while [`MAX_QUEUED`] messages or more wait for the writer.
    pub(crate) async fn wait_for_room(&self) {
        let mut rx = self.queued.subscribe();
        drop(rx.wait_for(|n| *n < MAX_QUEUED).await);
    }

    fn queued_add(&self) {
        self.queued.send_modify(|n| *n = n.saturating_add(1));
    }

    fn queued_sub(&self) {
        self.queued.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// The FIFO of everything a session sends: replies (through
/// [`super::ReplyTo`]) and signals. Cheap to clone; usable from any thread.
/// Once the session is closed, sends are dropped (and report `false`).
#[derive(Clone)]
pub struct Outbox {
    sid: SessionId,
    tx: mpsc::UnboundedSender<Outgoing>,
    budget: Arc<FlowBudget>,
    link: Arc<Link>,
}

impl fmt::Debug for Outbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbox")
            .field("sid", &self.sid)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Outbox {
    /// The session this outbox belongs to.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.sid
    }

    /// Enqueues a signal that is not flow-controlled (`ConsentChanged`,
    /// `LocationsChanged`, `NearbyChanged`, `ListDone`, `JobProgress`,
    /// `JobFinished`, `Question`). False when the session is closed or the
    /// signal cannot be encoded.
    #[must_use = "false: the session is closed"]
    pub fn signal(&self, signal: &OutSignal) -> bool {
        signal.build().is_ok_and(|message| self.send_message(message, 0))
    }

    /// The session's byte budget for streamed signals.
    #[must_use]
    pub const fn flow(&self) -> &Arc<FlowBudget> {
        &self.budget
    }

    /// Enqueues a streamed signal (`ListBatch`, `WalkBatch`) whose
    /// `acquired` bytes the producer took from [`Outbox::flow`]; the writer
    /// gives them back after the send. On failure they are given back here.
    #[must_use = "false: the session is closed"]
    pub fn send_streamed(&self, signal: &OutSignal, acquired: usize) -> bool {
        let sent = signal.build().is_ok_and(|message| self.send_message(message, acquired));
        if !sent {
            self.budget.release(acquired);
        }
        sent
    }

    /// [`FlowBudget::acquire`] then [`Outbox::send_streamed`]: blocks while
    /// the budget is used up (worker threads only). False when canceled or
    /// when the session is gone.
    #[must_use = "false: canceled, or the session is closed"]
    pub fn stream(&self, signal: &OutSignal, bytes: usize, cancel: &AtomicBool) -> bool {
        self.budget.acquire(bytes, cancel) && self.send_streamed(signal, bytes)
    }

    /// Closes the connection without sending anything else (XB-6
    /// revocation). The session then reports `Event::Closed`.
    pub fn close(&self) {
        self.link.close();
    }

    /// Whether the session is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.link.is_closed()
    }

    pub(crate) fn send_message(&self, message: Message, flow_bytes: usize) -> bool {
        if self.is_closed() {
            return false;
        }
        self.link.queued_add();
        if self.tx.send(Outgoing { message, flow_bytes }).is_err() {
            self.link.queued_sub();
            return false;
        }
        true
    }
}

/// A new outbox and the receiving end for its writer.
pub(crate) fn outbox(
    sid: SessionId,
    link: Arc<Link>,
    limit: usize,
) -> (Outbox, mpsc::UnboundedReceiver<Outgoing>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Outbox { sid, tx, budget: Arc::new(FlowBudget::new(limit)), link }, rx)
}

/// The default budget of a session.
pub(crate) const SESSION_FLOW_LIMIT: usize = FLOW_LIMIT;

/// The session's single writer: sends in FIFO order until the link closes or
/// a send fails, then closes the link and the budget and drops what is left
/// (giving its bytes back).
pub(crate) async fn run_writer(
    conn: zbus::Connection,
    mut rx: mpsc::UnboundedReceiver<Outgoing>,
    link: Arc<Link>,
    budget: Arc<FlowBudget>,
) {
    loop {
        let next = tokio::select! {
            biased;
            () = link.wait_closed() => None,
            out = rx.recv() => out,
        };
        let Some(out) = next else { break };
        let sent = tokio::select! {
            biased;
            () = link.wait_closed() => false,
            r = conn.send(&out.message) => r.is_ok(),
        };
        budget.release(out.flow_bytes);
        link.queued_sub();
        if !sent {
            break;
        }
    }
    link.close();
    budget.close();
    rx.close();
    while let Ok(out) = rx.try_recv() {
        budget.release(out.flow_bytes);
        link.queued_sub();
    }
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
