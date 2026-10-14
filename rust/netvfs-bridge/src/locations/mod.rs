// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a consumer may reach (SPEC-v2 XB-7) and how (design §3.2, §3.3):
//! location specs ([`spec`]), their connection pools with lanes and the
//! per-host limit ([`pool`], XB-12), one std thread per backend connection
//! ([`worker`], C-8), the copy jobs on threads of their own ([`copyjobs`]),
//! the connection policy for accounts and ad-hoc locations ([`connector`],
//! XB-14, C-7), the book that holds them for the core ([`book`]) and the
//! pins of ad-hoc locations ([`knownhosts`], XB-14).
//!
//! # Threads
//!
//! The book, the pools and the copy jobs belong to the core actor (no
//! locks). Each worker is a std thread named `nvb-w` that owns its
//! [`ffi::Conn`](crate::ffi::Conn); each copy job a thread `nvb-copy` with
//! two. Shared across threads are only the per-operation [`CancelToken`]s
//! and each worker's queue (a mutex with its connection's cancel handle).
//!
//! # Worker → core
//!
//! Workers and copy jobs report what needs the core through
//! [`WorkerEvents`] ([`WorkerEvent`]): questions to a session and their
//! withdrawal, an account's connection data, an account's attention state,
//! a finished copy job and warnings for the log. The core folds
//! `WorkerEvent` into its own event enum (`core::Event`); the results of
//! ordinary work items are sent by the work closures the core builds.

pub mod book;
pub mod connector;
pub mod copyjobs;
pub mod knownhosts;
#[cfg(test)]
mod mock;
pub mod pool;
pub mod spec;
pub mod worker;

use crate::Status;
use crate::server::SessionId;
use connector::AccountAccess;
use copyjobs::CopyId;
use spec::Attention;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use zbus::zvariant::OwnedValue;
use zeroize::Zeroizing;

/// The cancel flag of one request or job (XB-13): set by the core, polled
/// by workers, descriptor devices and question waits.
pub type CancelToken = Arc<AtomicBool>;

/// Who a piece of work is for: the session (for questions) and the
/// request's cancel flag.
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// The session whose request this is (questions go there).
    pub session: SessionId,
    /// Set when the request is canceled.
    pub cancel: CancelToken,
}

impl TaskContext {
    /// The context of a request of `session`.
    #[must_use]
    pub const fn new(session: SessionId, cancel: CancelToken) -> Self {
        Self { session, cancel }
    }

    /// Work for no session that nobody cancels (closing a handle).
    #[must_use]
    pub fn detached() -> Self {
        Self { session: SessionId(0), cancel: Arc::new(AtomicBool::new(false)) }
    }

    /// Whether the request was canceled.
    #[must_use]
    pub fn canceled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

/// `Canceled` without a message, as a canceled request ends.
#[must_use]
pub fn canceled() -> Status {
    Status::new(netvfs_bridge_proto::ErrorName::Canceled, "")
}

/// One question a worker asks (identity-unknown, keyboard-interactive),
/// unique in the process; [`WorkerEvent::CancelQuestion`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AskId(pub u64);

impl AskId {
    /// A new id.
    #[must_use]
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A consumer's answer to a question (`Answer` call, XB-10).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Answer {
    /// Whether the consumer accepted.
    pub accept: bool,
    /// Keyboard-interactive answers, one per prompt; wiped on drop.
    pub answers: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer").field("accept", &self.accept).field("answers", &self.answers.len()).finish()
    }
}

/// What a worker or copy job needs from the core (design §3.3). Fold into
/// `core::Event`.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Ask `session` a question (`Question` signal) and send the answer, or
    /// `None` when there is none (no such session, the session went away,
    /// the question was dropped), through `answer`, once. The worker waits
    /// at most the question timeout and withdraws it with
    /// [`WorkerEvent::CancelQuestion`] when it stops waiting.
    Ask {
        /// The question's id on the worker side.
        ask: AskId,
        /// The session whose request opened the connection.
        session: SessionId,
        /// `identity-unknown` or `keyboard-interactive`.
        kind: &'static str,
        /// The `a{sv}` of the `Question` signal.
        details: HashMap<String, OwnedValue>,
        /// Where the answer goes.
        answer: mpsc::Sender<Option<Answer>>,
    },
    /// The worker stopped waiting (canceled, timed out): withdraw the
    /// question if it is still pending.
    CancelQuestion(AskId),
    /// What a connection to the account needs (the helper's `files`
    /// answer, XA-4): send it through `reply`, once.
    FetchAccount {
        /// The account.
        account_id: i32,
        /// Where the answer goes.
        reply: mpsc::Sender<Result<AccountAccess, Status>>,
    },
    /// XB-14: an account's connection failed at the identity check or at
    /// authentication; record the state (the helper's `attention`) and
    /// relist the accounts.
    Attention {
        /// The account.
        account_id: i32,
        /// The new state.
        attention: Attention,
        /// The identity pin seen, for review in Settings; may be empty.
        pin: String,
    },
    /// A copy job's thread has ended: call
    /// [`CopyJobs::finish`](copyjobs::CopyJobs::finish) and report the
    /// result.
    CopyDone {
        /// The job.
        id: CopyId,
        /// How it ended.
        result: Result<(), Status>,
    },
    /// Something for the warning log.
    Warning(String),
}

/// Where workers send [`WorkerEvent`]s: any function, typically one that
/// forwards into the core's channel. Called from std threads; must not
/// block.
#[derive(Clone)]
pub struct WorkerEvents(Arc<dyn Fn(WorkerEvent) + Send + Sync>);

impl WorkerEvents {
    /// Events go to `deliver`.
    pub fn new(deliver: impl Fn(WorkerEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(deliver))
    }

    /// Events go into an unbounded channel (and are dropped once its
    /// receiver is gone).
    #[must_use]
    pub fn channel(tx: tokio::sync::mpsc::UnboundedSender<WorkerEvent>) -> Self {
        Self::new(move |event| {
            // A closed channel means the core has stopped: nothing to do.
            drop(tx.send(event));
        })
    }

    /// Sends `event`.
    pub fn send(&self, event: WorkerEvent) {
        (self.0)(event);
    }
}

impl fmt::Debug for WorkerEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WorkerEvents")
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    #[test]
    fn task_context_and_canceled() {
        let token = Arc::new(AtomicBool::new(false));
        let task = TaskContext::new(SessionId(4), Arc::clone(&token));
        assert_eq!(task.session, SessionId(4));
        assert!(!task.canceled());
        token.store(true, Ordering::Release);
        assert!(task.canceled());
        let detached = TaskContext::detached();
        assert_eq!(detached.session, SessionId(0));
        assert!(!detached.canceled());
        let c = canceled();
        assert_eq!((c.name, c.message.as_str()), (ErrorName::Canceled, ""));
    }

    #[test]
    fn ask_ids_are_unique_and_answers_hide_secrets() {
        let (a, b) = (AskId::next(), AskId::next());
        assert!(b > a);
        let answer = Answer { accept: true, answers: vec![Zeroizing::new(b"123456".to_vec())] };
        let text = format!("{answer:?}");
        assert!(text.contains("accept: true") && text.contains("answers: 1"), "{text}");
        assert!(!text.contains("49"), "{text}");
    }

    #[test]
    fn events_reach_the_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let events = WorkerEvents::channel(tx);
        assert_eq!(format!("{events:?}"), "WorkerEvents");
        events.send(WorkerEvent::Warning("w".into()));
        assert!(matches!(rx.try_recv(), Ok(WorkerEvent::Warning(w)) if w == "w"));
        drop(rx);
        // A gone core: dropped quietly.
        events.send(WorkerEvent::CancelQuestion(AskId(1)));
    }
}
