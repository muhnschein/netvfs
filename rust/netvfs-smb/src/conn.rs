// SPDX-License-Identifier: LGPL-2.1-or-later
//! One SMB connection with one session (design §5): message ids and the
//! credit window, the integrity rules, and two tasks: one writes frames,
//! one reads them and hands each response to the request waiting for it.
//!
//! Integrity rules, applied to every received message before anything in
//! it is used:
//! - Before the session has keys (NEGOTIATE, SESSION_SETUP rounds) nothing
//!   can be checked; the preauth hash binds those messages to the keys.
//! - A request that went encrypted must be answered in a TRANSFORM_HEADER
//!   that authenticates, errors and interim responses too.
//! - A signed request must be answered signed, with a valid AES-CMAC
//!   signature, except by an interim STATUS_PENDING response
//!   (MS-SMB2 3.2.5.1.3).
//! - A protected message must name the session.
//! - A compressed frame (0xFC 'SMB') is refused: compression is never
//!   offered.
//! - A response must answer an outstanding request, by message id and
//!   command; a replayed response finds none.
//!
//! Any violation ends the connection: nothing of the message is used, and
//! what else an attacker or a broken server did cannot be known.
//!
//! A request is built, signed or sealed and queued for the writer in one
//! step under the state lock, so that a call dropped at any await (the
//! runtime drops a call one GRACE after cancel) never leaves half a
//! request. A dropped [`Ticket`] sends SMB2 CANCEL, and its response is
//! discarded when it comes; a CREATE abandoned that way is closed then.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::Duration;

use netvfs_vfs::CancelToken;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

use crate::crypto::{CryptoError, OpenKey, SealKey, SessionKeys, SigningKey, TRANSFORM_PROTOCOL_ID};
use crate::error::{Error, Result, policy, protocol};
use crate::msg::file::{Created, FileId, close_request};
use crate::msg::session::four_byte_request;
use crate::msg::{
    COMPRESSED_PROTOCOL_ID, Command, HEADER_LEN, Header, NOTIFICATION_MID, build, check_error_response,
    command_name, flags, split_chain,
};
use crate::status::NtStatus;
use crate::transport::{self, INITIAL_MAX_FRAME};

/// Credits kept in hand: requests ask for enough to come back to this.
pub const CREDIT_TARGET: u32 = 128;
/// Never count more credits than this; the server cannot grow the state.
const CREDIT_CAP: u32 = 8192;
/// Interim responses accepted for one request.
const MAX_INTERIM: u8 = 8;
/// One credit's worth of payload (MS-SMB2 3.1.5.2).
pub const CREDIT_UNIT: usize = 65_536;
/// How long `close` waits for the last frames to go out.
const CLOSE_WAIT: Duration = Duration::from_millis(500);
/// Why calls fail after `close`.
pub const CLOSED: &str = "the connection was closed";

/// How a request is protected, and so how its response must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protect {
    /// NEGOTIATE, SESSION_SETUP, a guest session.
    None,
    /// AES-CMAC signature.
    Sign,
    /// TRANSFORM_HEADER with AES-GCM.
    Encrypt,
}

/// Where a request goes: a tree (0: the session itself) and whether the
/// tree wants encryption (ENCRYPT_DATA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// TreeId.
    pub tree_id: u32,
    /// Requests on it are encrypted whatever the session does.
    pub encrypt: bool,
}

impl Target {
    /// Session-level requests (ECHO, LOGOFF, TREE_CONNECT).
    pub const SESSION: Self = Self { tree_id: 0, encrypt: false };
}

/// One request of a chain.
#[derive(Debug)]
pub struct Element {
    /// The command.
    pub command: Command,
    /// Its body.
    pub body: Vec<u8>,
    /// The larger of the request's and the expected response's payload,
    /// for the credit charge.
    pub payload: usize,
    /// Compounded with the element before it, on its file.
    pub related: bool,
    /// A CREATE whose handle no later element of the chain closes: the
    /// caller closes it, or the connection does if the caller goes.
    pub owns_handle: bool,
}

impl Element {
    /// A request of one credit's payload at most.
    #[must_use]
    pub fn new(command: Command, body: Vec<u8>) -> Self {
        Self { command, body, payload: 1, related: false, owns_handle: false }
    }

    /// With a payload of `bytes`.
    #[must_use]
    pub fn payload(mut self, bytes: usize) -> Self {
        self.payload = bytes;
        self
    }

    /// Related to the element before it.
    #[must_use]
    pub fn related(mut self) -> Self {
        self.related = true;
        self
    }

    /// A CREATE whose handle outlives the chain.
    #[must_use]
    pub fn owning(mut self) -> Self {
        self.owns_handle = true;
        self
    }
}

/// A response that passed the integrity rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Its header.
    pub header: Header,
    /// The message: header and body (padding of a chain element included).
    pub msg: Vec<u8>,
}

impl Response {
    /// The NT status.
    #[must_use]
    pub fn status(&self) -> NtStatus {
        self.header.status
    }

    /// `Ok` for STATUS_SUCCESS, else the status (after checking that an
    /// error response has a well-formed ERROR body).
    ///
    /// # Errors
    /// [`Error::Status`], or a protocol error for a malformed ERROR body.
    pub fn ok(&self) -> Result<()> {
        self.expect(&[]).map(drop)
    }

    /// The status when it is STATUS_SUCCESS or one of `accepted` (whose
    /// bodies the caller decodes); else as [`Self::ok`].
    ///
    /// # Errors
    /// As [`Self::ok`].
    pub fn expect(&self, accepted: &[NtStatus]) -> Result<NtStatus> {
        let status = self.status();
        if status == NtStatus::SUCCESS || accepted.contains(&status) {
            return Ok(status);
        }
        check_error_response(&self.msg)?;
        Err(Error::Status(status))
    }
}

/// The receive-side keys of the session (shared with the reader, which
/// checks outside the lock).
#[derive(Debug)]
struct Keys {
    signing: SigningKey,
    open: Option<OpenKey>,
}

/// A request waiting for its final response.
#[derive(Debug)]
struct Pending {
    command: u16,
    protect: Protect,
    tree_id: u32,
    /// `None` once the caller abandoned it.
    tx: Option<oneshot::Sender<Result<Response>>>,
    async_id: Option<u64>,
    interims: u8,
    deadline: Instant,
    owns_handle: bool,
}

/// The message ids of a dispatched chain and their receivers (none for a
/// detached chain).
type Sent = Vec<(u64, Option<oneshot::Receiver<Result<Response>>>)>;

#[derive(Debug)]
struct State {
    next_mid: u64,
    credits: u32,
    multi_credit: bool,
    max_frame: usize,
    session_id: u64,
    keys: Option<Arc<Keys>>,
    seal: Option<SealKey>,
    /// Session.EncryptData: every request is encrypted.
    encrypt: bool,
    established: bool,
    pending: HashMap<u64, Pending>,
    /// To the writer; `None` once the connection is broken or closed.
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    broken: Option<Error>,
    timeout: Duration,
    reader: Option<AbortHandle>,
    writer: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// Credits came back, or the connection broke.
    credits: Notify,
}

/// A connection; clones share it.
#[derive(Debug, Clone)]
pub struct Conn(Arc<Shared>);

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing panics while holding the lock; if something did, the
        // state is still consistent enough to fail the calls.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the connection with `error` (the first reason wins).
    fn break_with(&self, error: Error) {
        self.lock().fail(error);
        self.credits.notify_waiters();
    }
}

impl State {
    /// What a call sees of a failure: once established, every way of
    /// losing the connection is [`Error::Lost`] (XC-21).
    fn failure(&self, error: &Error) -> Error {
        match error {
            Error::Lost(_) => error.clone(),
            other if self.established => Error::Lost(other.to_string()),
            other => other.clone(),
        }
    }

    fn usable(&self) -> Result<()> {
        self.broken.as_ref().map_or(Ok(()), |e| Err(self.failure(e)))
    }

    fn fail(&mut self, error: Error) {
        if self.broken.is_some() {
            return;
        }
        let seen = self.failure(&error);
        self.broken = Some(error);
        self.tx = None;
        for (_, entry) in self.pending.drain() {
            if let Some(tx) = entry.tx {
                // The caller may be gone already.
                drop(tx.send(Err(seen.clone())));
            }
        }
        self.seal = None;
    }

    fn protect(&self, target: Target) -> Protect {
        match self.keys {
            None => Protect::None,
            Some(_) if self.encrypt || target.encrypt => Protect::Encrypt,
            Some(_) => Protect::Sign,
        }
    }

    /// Credits and message ids a request of `payload` bytes takes.
    fn cost(&self, command: Command, payload: usize) -> Result<u16> {
        if command == Command::Negotiate || payload <= CREDIT_UNIT {
            return Ok(1);
        }
        if !self.multi_credit {
            return Err(Error::Local(netvfs_vfs::Status::internal(format!(
                "{}: {payload} bytes need multi-credit requests",
                command.name()
            ))));
        }
        u16::try_from(payload.div_ceil(CREDIT_UNIT))
            .map_err(|_overflow| Error::Local(netvfs_vfs::Status::internal("request too large")))
    }

    /// Builds, protects and queues `elements` as one chain. Returns the
    /// message ids and receivers (none for `detached` requests, whose
    /// responses are discarded) and the plain chain (for the preauth
    /// hash). The caller checked that the credits suffice.
    fn dispatch(
        &mut self,
        tree_id: u32,
        protect: Protect,
        elements: &[Element],
        detached: bool,
    ) -> Result<(Sent, Vec<u8>)> {
        self.usable()?;
        let costs = elements.iter().map(|e| self.cost(e.command, e.payload)).collect::<Result<Vec<u16>>>()?;
        let total: u32 = costs.iter().map(|c| u32::from(*c)).sum();
        if total > self.credits {
            return Err(protocol(format!("{total} credits needed, {} granted", self.credits)));
        }
        let first_mid = self.next_mid;
        let end = first_mid
            .checked_add(u64::from(total))
            .filter(|m| *m < NOTIFICATION_MID)
            .ok_or_else(|| protocol("message ids used up"))?;
        let left = self.credits.saturating_sub(total);
        let top_up = CREDIT_TARGET.saturating_sub(left);
        let keys = self.keys.clone();
        let mut chain = Vec::new();
        let mut entries = Vec::new();
        let mut mid = first_mid;
        let count = elements.len();
        let deadline = after(self.timeout);
        let last = count.saturating_sub(1);
        for (i, (element, cost)) in elements.iter().zip(costs).enumerate() {
            let mut header = Header::request(element.command, mid, self.session_id, tree_id);
            header.credit_charge = if element.command == Command::Negotiate { 0 } else { cost };
            let ask = if i == 0 { u32::from(cost).max(top_up) } else { u32::from(cost) };
            header.credits = u16::try_from(ask).unwrap_or(u16::MAX);
            if element.related {
                header.flags |= flags::RELATED_OPERATIONS;
            }
            if protect == Protect::Sign {
                header.flags |= flags::SIGNED;
            }
            let padded = HEADER_LEN.saturating_add(element.body.len()).next_multiple_of(8);
            if i < last {
                header.next_command = crate::wire::to_u32(padded)?;
            }
            let mut msg = build(&header, &element.body);
            if i < last {
                msg.resize(padded, 0);
            }
            if protect == Protect::Sign {
                let keys = keys.as_ref().ok_or_else(|| protocol("signing without session keys"))?;
                keys.signing.sign(&mut msg).map_err(|e| integrity("sign", e))?;
            }
            chain.extend_from_slice(&msg);
            entries.push((mid, element.command.code(), element.owns_handle));
            mid = mid.saturating_add(u64::from(cost));
        }
        let wire = match protect {
            Protect::Encrypt => {
                let seal = self.seal.as_mut().ok_or_else(|| protocol("encryption without a session key"))?;
                match seal.seal(&chain) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        let error = policy(format!("cannot encrypt: {e}"));
                        self.fail(error.clone());
                        return Err(self.failure(&error));
                    }
                }
            }
            Protect::None | Protect::Sign => chain.clone(),
        };
        let frame = transport::frame(&wire)?;
        self.next_mid = end;
        self.credits = left;
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(frame).is_ok());
        if !sent {
            let error = Error::Lost("the connection is closed".into());
            self.fail(error.clone());
            return Err(self.failure(&error));
        }
        let mut out = Vec::new();
        for (mid, command, owns_handle) in entries {
            let (tx, rx) = if detached {
                (None, None)
            } else {
                let (tx, rx) = oneshot::channel();
                (Some(tx), Some(rx))
            };
            self.pending.insert(
                mid,
                Pending { command, protect, tree_id, tx, async_id: None, interims: 0, deadline, owns_handle },
            );
            out.push((mid, rx));
        }
        Ok((out, chain))
    }

    /// Dispatches `elements` when the credits suffice (`None`: wait for
    /// more).
    fn try_dispatch(
        &mut self,
        target: Target,
        elements: &[Element],
        need: u32,
        cancel: &CancelToken,
    ) -> Result<Option<(Sent, Vec<u8>, Protect)>> {
        self.usable()?;
        if cancel.is_canceled() {
            return Err(Error::Canceled);
        }
        if self.credits >= need {
            let protect = self.protect(target);
            let (sent, chain) = self.dispatch(target.tree_id, protect, elements, false)?;
            return Ok(Some((sent, chain, protect)));
        }
        if self.pending.is_empty() {
            return Err(protocol(format!(
                "the server granted {} credits, and {need} are needed",
                self.credits
            )));
        }
        Ok(None)
    }

    /// Takes the credits of a checked response; for a final one, the
    /// request is done: returns where the response goes (`None`: nowhere).
    fn accept(
        &mut self,
        header: &Header,
        element: &[u8],
    ) -> Result<Option<oneshot::Sender<Result<Response>>>> {
        self.usable()?;
        self.credits = self.credits.saturating_add(u32::from(header.credits)).min(CREDIT_CAP);
        let mid = header.message_id;
        if header.is_interim() {
            let timeout = self.timeout;
            let entry = self.pending.get_mut(&mid).ok_or_else(|| protocol("request gone"))?;
            entry.interims = entry.interims.saturating_add(1);
            if entry.interims > MAX_INTERIM {
                return Err(protocol("too many interim responses to one request"));
            }
            entry.async_id = header.async_id;
            entry.deadline = after(timeout);
            return Ok(None);
        }
        let entry = self.pending.remove(&mid).ok_or_else(|| protocol("request gone"))?;
        if entry.tx.is_none()
            && entry.owns_handle
            && header.command == Command::Create.code()
            && header.status == NtStatus::SUCCESS
            && let Ok(created) = Created::decode(element)
        {
            self.close_detached(entry.tree_id, entry.protect, &created.file_id);
        }
        Ok(entry.tx)
    }

    /// SMB2 CANCEL of an outstanding request (MS-SMB2 3.2.4.24): no credit,
    /// no message id of its own, protected as the request was.
    fn send_cancel(&mut self, mid: u64) {
        let Some(entry) = self.pending.get(&mid) else { return };
        let mut header = Header::request(Command::Cancel, mid, self.session_id, entry.tree_id);
        if let Some(id) = entry.async_id {
            header.flags |= flags::ASYNC_COMMAND;
            header.async_id = Some(id);
        }
        let protect = entry.protect;
        if protect == Protect::Sign {
            header.flags |= flags::SIGNED;
        }
        let mut msg = build(&header, &four_byte_request());
        let wire = match (protect, self.keys.as_ref()) {
            (Protect::Sign, Some(keys)) => keys.signing.sign(&mut msg).ok().map(|()| msg),
            (Protect::Encrypt, _) => self.seal.as_mut().and_then(|s| s.seal(&msg).ok()),
            (Protect::None, _) => Some(msg),
            (Protect::Sign, None) => None,
        };
        // A CANCEL that cannot go is only a request that runs to its end.
        if let (Some(wire), Some(tx)) = (wire, self.tx.as_ref())
            && let Ok(frame) = transport::frame(&wire)
        {
            drop(tx.send(frame));
        }
    }

    /// Closes a handle nobody waits for any more, if a credit is at hand.
    fn close_detached(&mut self, tree_id: u32, protect: Protect, file_id: &FileId) {
        if self.credits == 0 {
            return;
        }
        // Best effort: on failure the handle lives until the session ends.
        drop(self.dispatch(tree_id, protect, &[Element::new(Command::Close, close_request(file_id))], true));
    }
}

/// A failure of the crypto glue.
fn integrity(what: &str, e: CryptoError) -> Error {
    policy(format!("{what}: {e}"))
}

impl Conn {
    /// Starts the reader and writer tasks on `stream` (inside a tokio
    /// runtime); requests time out after `timeout`.
    #[must_use]
    pub fn start(stream: TcpStream, timeout: Duration) -> Self {
        let (rd, wr) = stream.into_split();
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                next_mid: 0,
                credits: 1,
                multi_credit: false,
                max_frame: INITIAL_MAX_FRAME,
                session_id: 0,
                keys: None,
                seal: None,
                encrypt: false,
                established: false,
                pending: HashMap::new(),
                tx: Some(tx),
                broken: None,
                timeout,
                reader: None,
                writer: None,
            }),
            credits: Notify::new(),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&shared), rd));
        let writer = tokio::spawn(write_loop(Arc::clone(&shared), wr, rx));
        {
            let mut st = shared.lock();
            st.reader = Some(reader.abort_handle());
            st.writer = Some(writer);
        }
        Self(shared)
    }

    /// The request timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.0.lock().timeout
    }

    /// After NEGOTIATE: the largest frame accepted and whether requests may
    /// take several credits.
    pub fn set_limits(&self, max_frame: usize, multi_credit: bool) {
        let mut st = self.0.lock();
        st.max_frame = max_frame.min(transport::MAX_FRAME_FORMAT);
        st.multi_credit = multi_credit;
    }

    /// The SessionId the next requests carry (SESSION_SETUP rounds).
    pub fn set_session_id(&self, id: u64) {
        self.0.lock().session_id = id;
    }

    /// The session's SessionId.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.0.lock().session_id
    }

    /// Ends sign-in: from now on requests are signed with `keys` (sealed
    /// when the session or the tree encrypts); without keys (guest) nothing
    /// is. Calls that lose the connection after this fail with
    /// [`Error::Lost`].
    pub fn establish(&self, keys: Option<SessionKeys>, encrypt: bool) {
        let mut st = self.0.lock();
        if let Some(keys) = keys {
            st.keys = Some(Arc::new(Keys { signing: keys.signing, open: keys.open }));
            st.seal = keys.seal;
        }
        st.encrypt = encrypt;
        st.established = true;
    }

    /// Whether requests can be encrypted (a cipher and keys).
    #[must_use]
    pub fn can_encrypt(&self) -> bool {
        self.0.lock().seal.is_some()
    }

    /// Whether every request is encrypted.
    #[must_use]
    pub fn encrypts(&self) -> bool {
        self.0.lock().encrypt
    }

    /// Credits granted and unused (tests, logs).
    #[must_use]
    pub fn credits(&self) -> u32 {
        self.0.lock().credits
    }

    /// `Ok` while the connection works.
    ///
    /// # Errors
    /// Why it does not.
    pub fn usable(&self) -> Result<()> {
        self.0.lock().usable()
    }

    /// Sends `elements` as one chain to `target` once credits allow, and
    /// returns one ticket per element.
    ///
    /// # Errors
    /// A broken connection, cancel, no credits in time.
    pub async fn send(
        &self,
        target: Target,
        elements: Vec<Element>,
        cancel: &CancelToken,
    ) -> Result<Vec<Ticket>> {
        Ok(self.send_raw(target, elements, cancel).await?.0)
    }

    /// As [`Self::send`], with the plain chain as sent (for the preauth hash).
    async fn send_raw(
        &self,
        target: Target,
        elements: Vec<Element>,
        cancel: &CancelToken,
    ) -> Result<(Vec<Ticket>, Vec<u8>)> {
        let owners: Vec<bool> = elements.iter().map(|e| e.owns_handle).collect();
        let need = {
            let st = self.0.lock();
            let mut need = 0u32;
            for e in &elements {
                need = need.saturating_add(u32::from(st.cost(e.command, e.payload)?));
            }
            need
        };
        let deadline = after(self.timeout());
        let mut canceled = pin!(cancel.canceled());
        loop {
            let notified = self.0.credits.notified();
            let mut notified = pin!(notified);
            notified.as_mut().enable();
            let dispatched = self.0.lock().try_dispatch(target, &elements, need, cancel)?;
            if let Some((sent, chain, protect)) = dispatched {
                let tickets = sent
                    .into_iter()
                    .zip(owners)
                    .filter_map(|((mid, rx), owns)| {
                        rx.map(|rx| Ticket {
                            shared: Arc::clone(&self.0),
                            mid,
                            rx,
                            cleanup: owns.then_some((target.tree_id, protect)),
                            done: false,
                        })
                    })
                    .collect();
                return Ok((tickets, chain));
            }
            let mut sleep = pin!(tokio::time::sleep_until(deadline));
            let woke = poll_fn(|cx| {
                if notified.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Wake::Ready);
                }
                if canceled.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Wake::Canceled);
                }
                if sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Wake::Deadline);
                }
                Poll::Pending
            })
            .await;
            match woke {
                Wake::Ready => {}
                Wake::Canceled => return Err(Error::Canceled),
                Wake::Deadline => {
                    self.0.break_with(Error::Timeout);
                    return Err(Error::Timeout);
                }
            }
        }
    }

    /// Sends one request and waits for its final response.
    ///
    /// # Errors
    /// As [`Self::send`] and [`Ticket::wait`].
    pub async fn call(&self, target: Target, element: Element, cancel: &CancelToken) -> Result<Response> {
        let ticket = self.send(target, vec![element], cancel).await?.pop();
        ticket.ok_or_else(|| protocol("no ticket"))?.wait(cancel).await
    }

    /// Sends one unprotected sign-in request; returns its final response
    /// and the request as sent (MS-SMB2 3.2.5.2, 3.2.5.3.1: both go into
    /// the preauth hash).
    ///
    /// # Errors
    /// As [`Self::call`].
    pub async fn call_raw(&self, element: Element, cancel: &CancelToken) -> Result<(Response, Vec<u8>)> {
        let (mut tickets, sent) = self.send_raw(Target::SESSION, vec![element], cancel).await?;
        let ticket = tickets.pop().ok_or_else(|| protocol("no ticket"))?;
        Ok((ticket.wait(cancel).await?, sent))
    }

    /// Sends a chain and waits for all its responses, in order.
    ///
    /// # Errors
    /// As [`Self::call`].
    pub async fn compound(
        &self,
        target: Target,
        elements: Vec<Element>,
        cancel: &CancelToken,
    ) -> Result<Vec<Response>> {
        let tickets = self.send(target, elements, cancel).await?;
        let mut out = Vec::new();
        for ticket in tickets {
            out.push(ticket.wait(cancel).await?);
        }
        Ok(out)
    }

    /// Ends the connection: LOGOFF when `logoff` (not waited for), the
    /// queued frames go out (for at most half a second), then the socket
    /// closes. Calls fail with [`Error::Lost`] afterwards.
    pub async fn close(&self, logoff: bool) {
        let writer = {
            let mut st = self.0.lock();
            if logoff && st.broken.is_none() && st.established && st.credits > 0 {
                let protect = st.protect(Target::SESSION);
                // Best effort: the session ends with the socket anyway.
                drop(st.dispatch(0, protect, &[Element::new(Command::Logoff, four_byte_request())], true));
            }
            st.fail(Error::Lost(CLOSED.into()));
            st.writer.take()
        };
        self.0.credits.notify_waiters();
        if let Some(mut writer) = writer
            && tokio::time::timeout(CLOSE_WAIT, &mut writer).await.is_err()
        {
            writer.abort();
        }
        self.abort();
    }

    /// Stops both tasks at once (a backend dropped without disconnect).
    pub fn abort(&self) {
        let mut st = self.0.lock();
        st.fail(Error::Lost(CLOSED.into()));
        if let Some(reader) = st.reader.take() {
            reader.abort();
        }
        if let Some(writer) = st.writer.take() {
            writer.abort();
        }
        drop(st);
        self.0.credits.notify_waiters();
    }
}

enum Wake {
    Ready,
    Canceled,
    Deadline,
}

/// The claim on one request's final response. Dropping it before the
/// response came cancels the request (SMB2 CANCEL) and discards the
/// response; a CREATE whose handle the caller owns is then closed.
#[derive(Debug)]
pub struct Ticket {
    shared: Arc<Shared>,
    mid: u64,
    rx: oneshot::Receiver<Result<Response>>,
    /// Tree and protection for closing an owned handle nobody took.
    cleanup: Option<(u32, Protect)>,
    done: bool,
}

impl Ticket {
    /// The final response; `Canceled` as soon as `cancel` trips (the
    /// request is then canceled on the server), `Timeout` when the server
    /// does not answer within the request timeout (an interim response
    /// restarts it), which ends the connection.
    ///
    /// # Errors
    /// As described, and the connection's failures.
    pub async fn wait(mut self, cancel: &CancelToken) -> Result<Response> {
        let shared = Arc::clone(&self.shared);
        let mut canceled = pin!(cancel.canceled());
        loop {
            let deadline = shared.lock().pending.get(&self.mid).map(|p| p.deadline);
            let mut sleep = pin!(tokio::time::sleep_until(deadline.unwrap_or_else(far_future)));
            let rx = &mut self.rx;
            let woke = poll_fn(|cx| {
                if let Poll::Ready(r) = Pin::new(&mut *rx).poll(cx) {
                    return Poll::Ready(r.map_or(Woke::Closed, Woke::Response));
                }
                if canceled.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Woke::Canceled);
                }
                if sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Woke::Deadline);
                }
                Poll::Pending
            })
            .await;
            match woke {
                Woke::Response(result) => {
                    self.done = true;
                    return result;
                }
                Woke::Closed => {
                    self.done = true;
                    let st = shared.lock();
                    let e = st.broken.clone().unwrap_or_else(|| Error::Lost(CLOSED.into()));
                    return Err(st.failure(&e));
                }
                Woke::Deadline => {
                    let still = shared.lock().pending.get(&self.mid).map(|p| p.deadline);
                    if still.is_some_and(|d| d <= Instant::now()) {
                        shared.break_with(Error::Timeout);
                        return Err(Error::Timeout);
                    }
                }
                Woke::Canceled => return Err(Error::Canceled),
            }
        }
    }
}

/// Why a wait for a response woke.
enum Woke {
    /// The response, or the connection's failure.
    Response(Result<Response>),
    /// The sender went without sending.
    Closed,
    /// The token tripped.
    Canceled,
    /// The deadline passed (an interim response may have moved it).
    Deadline,
}

/// `d` from now.
fn after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or(now)
}

/// An instant no request waits for (a request without a deadline).
fn far_future() -> Instant {
    after(Duration::from_hours(24 * 365))
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut st = self.shared.lock();
        if let Some(entry) = st.pending.get_mut(&self.mid) {
            entry.tx = None;
            st.send_cancel(self.mid);
            return;
        }
        // The response came and nobody took it: an owned handle is closed.
        if let (Some((tree_id, protect)), Ok(Ok(response))) = (self.cleanup, self.rx.try_recv())
            && response.header.command == Command::Create.code()
            && response.status() == NtStatus::SUCCESS
            && let Ok(created) = Created::decode(&response.msg)
        {
            st.close_detached(tree_id, protect, &created.file_id);
        }
    }
}

/// Reads frames until the connection ends.
async fn read_loop(shared: Arc<Shared>, mut rd: OwnedReadHalf) {
    let error = loop {
        let max = shared.lock().max_frame;
        let frame = match transport::read_frame(&mut rd, max).await {
            Ok(frame) => frame,
            Err(e) => break e,
        };
        if let Err(e) = receive(&shared, frame) {
            break e;
        }
    };
    shared.break_with(error);
}

/// Writes queued frames until the queue closes, then shuts the socket down.
async fn write_loop(shared: Arc<Shared>, mut wr: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if let Err(e) = wr.write_all(&frame).await {
            shared.break_with(Error::Lost(e.to_string()));
            return;
        }
    }
    // The connection is over either way.
    drop(wr.shutdown().await);
}

/// One received frame: opened when encrypted, then each message of the
/// chain in it.
fn receive(shared: &Shared, frame: Vec<u8>) -> Result<()> {
    let keys = shared.lock().keys.clone();
    let (msg, encrypted) = match frame.get(..4) {
        Some(magic) if magic == TRANSFORM_PROTOCOL_ID => {
            let open = keys
                .as_ref()
                .and_then(|k| k.open.as_ref())
                .ok_or_else(|| policy("an encrypted message, but the session has no key"))?;
            (open.open(&frame).map_err(|e| integrity("received message", e))?, true)
        }
        Some(magic) if magic == COMPRESSED_PROTOCOL_ID => {
            return Err(policy("a compressed message; compression was not negotiated"));
        }
        _ => (frame, false),
    };
    for range in split_chain(&msg)? {
        let element = msg.get(range).ok_or_else(|| protocol("compound element outside the message"))?;
        response(shared, element, encrypted, keys.as_deref())?;
    }
    Ok(())
}

/// One received message (a chain element).
fn response(shared: &Shared, element: &[u8], encrypted: bool, keys: Option<&Keys>) -> Result<()> {
    let header = Header::decode(element)?;
    if !header.is_response() {
        return Err(protocol("the server sent a request"));
    }
    let mid = header.message_id;
    if mid == NOTIFICATION_MID {
        // Oplock and lease breaks, server-to-client notifications: none is
        // asked for, and nothing in them is used (credits included).
        return Ok(());
    }
    let (protect, session_id) = {
        let st = shared.lock();
        let entry = st.pending.get(&mid).ok_or_else(|| {
            protocol(format!("a {} response to no outstanding request", command_name(header.command)))
        })?;
        if entry.command != header.command {
            return Err(protocol(format!(
                "a {} response to a {} request",
                command_name(header.command),
                command_name(entry.command)
            )));
        }
        (entry.protect, st.session_id)
    };
    check(&header, element, encrypted, protect, session_id, keys)?;
    let delivery = shared.lock().accept(&header, element)?;
    shared.credits.notify_waiters();
    if let Some(tx) = delivery {
        // A caller that went just now drops the response with the receiver.
        drop(tx.send(Ok(Response { header, msg: element.to_vec() })));
    }
    Ok(())
}

/// The integrity rules of the module comment for one message.
fn check(
    header: &Header,
    element: &[u8],
    encrypted: bool,
    protect: Protect,
    session_id: u64,
    keys: Option<&Keys>,
) -> Result<()> {
    if protect != Protect::None && header.session_id != session_id {
        return Err(policy(format!("a {} response for another session", command_name(header.command))));
    }
    if encrypted {
        return Ok(());
    }
    match protect {
        Protect::None => Ok(()),
        Protect::Encrypt => Err(policy(format!(
            "an unencrypted {} response ({}) on an encrypted connection",
            command_name(header.command),
            header.status
        ))),
        Protect::Sign if header.is_interim() => Ok(()),
        Protect::Sign => {
            if !header.is_signed() {
                return Err(policy(format!(
                    "an unsigned {} response ({}) on a signed connection",
                    command_name(header.command),
                    header.status
                )));
            }
            let keys = keys.ok_or_else(|| protocol("no session keys"))?;
            keys.signing
                .verify(element)
                .map_err(|e| integrity(&format!("{} response", command_name(header.command)), e))
        }
    }
}

#[cfg(test)]
mod tests;
