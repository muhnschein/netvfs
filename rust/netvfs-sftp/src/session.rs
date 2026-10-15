// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SSH transport (S-1 to S-7) over russh: TCP within the connect
//! timeout, the hardened algorithm lists (narrowed to a pinned key type,
//! S-5), the server's identity (S-6), keep-alive (XS-12) and the `sftp`
//! subsystem channel. Signing in is [`crate::auth`]'s.
//!
//! russh runs the session in a task of its own, which ends when its
//! stream does. The stream here can be cut ([`Cut`]): a [`Session`] that
//! is dropped, or a connect that is dropped half way, cuts it, so no
//! session task outlives its connection, whatever a stalled server does.

use crate::errors::{connection_lost, timed_out};
use crate::policy;
use netvfs_vfs::{CancelToken, ErrorName, ServerIdentity, Status};
use russh::client::{self, ChannelOpenHandle, DisconnectReason, Handle, Msg};
use russh::keys::{PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect};
use std::future::{Future, ready};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Port 22 (S-1).
pub const DEFAULT_PORT: u16 = 22;
/// How long [`Session::close`] waits for the session task to send its
/// `DISCONNECT` before the stream is cut.
const CLOSE_WAIT: Duration = Duration::from_millis(500);
/// The global request of XS-12.
const KEEPALIVE: &str = "keepalive@openssh.com";

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or address literal.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// For TCP and the SSH handshake together (C-14).
    pub connect_timeout: Duration,
    /// The pinned host key type, if any: the host-key list is narrowed to
    /// it (S-5).
    pub pinned_type: Option<String>,
}

/// Why a session ended, as the handler saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The server sent `DISCONNECT` with this reason code and text.
    Disconnected {
        /// RFC 4253 11.1 reason code.
        code: u32,
        /// The server's description.
        message: String,
    },
    /// The server's `USERAUTH_FAILURE` named no method to continue with.
    NoAuthMethod,
    /// The transport failed (I/O, protocol): russh's description.
    Failed(String),
}

impl End {
    /// `ConnectionLost`, with what ended the session as the detail.
    #[must_use]
    pub fn status(&self) -> Status {
        let detail = match self {
            Self::Disconnected { code, message } => {
                format!("The server closed the connection ({code}): {message}")
            }
            Self::NoAuthMethod => "The server named no sign-in method".to_owned(),
            Self::Failed(text) => text.clone(),
        };
        connection_lost().with_detail(detail)
    }
}

/// What the handler saw: the host key, the end.
#[derive(Debug, Default)]
struct Seen {
    host_key: Option<PublicKey>,
    end: Option<End>,
}

#[derive(Debug, Clone, Default)]
struct Shared(Arc<Mutex<Seen>>);

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Seen> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The russh handler of a [`Session`]: records the host key (the caller
/// compares it with the pin, S-7) and how the session ended; refuses every
/// channel the server wants to open (dropping the reply refuses it,
/// administratively prohibited).
#[derive(Debug)]
pub struct Recorder {
    seen: Shared,
}

impl client::Handler for Recorder {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        ready({
            match key {
                PublicKeyOrCertificate::PublicKey { key, .. } => {
                    self.seen.lock().host_key = Some(key.clone());
                    Ok(true)
                }
                // Never negotiated: the lists hold no certificate algorithm.
                PublicKeyOrCertificate::Certificate(_) => Ok(false),
            }
        })
    }

    fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            let (end, result) = match reason {
                DisconnectReason::ReceivedDisconnect(info) => {
                    (End::Disconnected { code: info.reason_code as u32, message: info.message }, Ok(()))
                }
                DisconnectReason::Error(russh::Error::NoAuthMethod) => (End::NoAuthMethod, Ok(())),
                DisconnectReason::Error(e) => (End::Failed(e.to_string()), Err(e)),
            };
            self.seen.lock().end.get_or_insert(end);
            result
        })
    }

    fn server_channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_agent_forward(
        &mut self,
        _: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_x11(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_forwarded_tcpip(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_direct_tcpip(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }

    fn server_channel_open_direct_streamlocal(
        &mut self,
        _: Channel<Msg>,
        _: &str,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready({
            drop(reply);
            Ok(())
        })
    }
}

/// Ends a [`Cuttable`] stream: its reads and writes fail from then on,
/// also one that is waiting.
#[derive(Debug, Clone, Default)]
pub struct Cut(Arc<CutState>);

#[derive(Debug, Default)]
struct CutState {
    done: AtomicBool,
    /// The read and the write side's wakers.
    wakers: Mutex<[Option<Waker>; 2]>,
}

impl Cut {
    /// Cuts the stream.
    pub fn cut(&self) {
        self.0.done.store(true, Ordering::SeqCst);
        let wakers = std::mem::take(&mut *self.0.wakers.lock().unwrap_or_else(PoisonError::into_inner));
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    /// Whether the stream was cut.
    #[must_use]
    pub fn is_cut(&self) -> bool {
        self.0.done.load(Ordering::SeqCst)
    }

    /// `Err` once cut; else remembers `cx`'s waker for `side`.
    fn check(&self, side: usize, cx: &Context<'_>) -> io::Result<()> {
        if self.is_cut() {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        let mut wakers = self.0.wakers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = wakers.get_mut(side)
            && !slot.as_ref().is_some_and(|w| w.will_wake(cx.waker()))
        {
            *slot = Some(cx.waker().clone());
        }
        drop(wakers);
        // A cut between the first check and the registration took no
        // waker of ours.
        if self.is_cut() {
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        Ok(())
    }
}

/// Cuts on drop unless disarmed: a connect that is dropped half way ends
/// the session task it started.
#[derive(Debug)]
struct CutOnDrop(Option<Cut>);

impl CutOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CutOnDrop {
    fn drop(&mut self) {
        if let Some(cut) = &self.0 {
            cut.cut();
        }
    }
}

/// A stream that [`Cut`] can end.
#[derive(Debug)]
pub struct Cuttable<S> {
    inner: S,
    cut: Cut,
}

impl<S> Cuttable<S> {
    /// `inner`, and what cuts it.
    pub fn new(inner: S) -> (Self, Cut) {
        let cut = Cut::default();
        (Self { inner, cut: cut.clone() }, cut)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Cuttable<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.cut.check(0, cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Cuttable<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Err(e) = self.cut.check(1, cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.cut.check(1, cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cut.is_cut() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// An established SSH connection (not signed in yet, or signed in).
pub struct Session {
    handle: Handle<Recorder>,
    seen: Shared,
    cut: Cut,
    identity: ServerIdentity,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("identity", &self.identity)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cut.cut();
    }
}

/// The identity of a host key: its type, its blob, and the fingerprint
/// as `ssh-keygen -lf` prints it (S-6).
#[must_use]
pub fn identity_of(key: &PublicKey) -> ServerIdentity {
    ServerIdentity {
        algorithm: key.algorithm().as_str().to_owned(),
        public_key: key.to_bytes().unwrap_or_default(),
        fingerprint: crate::keys::fingerprint(key),
    }
}

/// Runs `work` under `cancel` and `timeout`.
///
/// # Errors
/// `work`'s, `Canceled`, or `Timeout`.
pub async fn bounded<T>(
    work: impl Future<Output = Result<T, Status>>,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<T, Status> {
    match tokio::time::timeout(timeout, cancel.guard(work)).await {
        Ok(result) => result,
        Err(_) => Err(timed_out(timeout.as_millis())),
    }
}

/// Connects (S-1, S-5, S-6). With a pinned type the host-key list is
/// narrowed to it; a server that no longer offers that type is connected
/// to once more without the restriction, so that the caller sees the key
/// it presents now (S-7).
///
/// # Errors
/// `NetworkUnreachable`, `Timeout`, `Canceled`, `SecurityPolicy` (no
/// algorithm in common), `ProtocolError`.
pub async fn connect(target: &Target, cancel: &CancelToken) -> Result<Session, Status> {
    let narrowed = target.pinned_type.as_deref().and_then(policy::pinned_algorithm);
    if narrowed.is_some() {
        match open(target, narrowed.as_ref(), cancel).await {
            Err(Opening::Ssh(e)) if policy::is_host_key_mismatch(&e) => {}
            other => return other.map_err(Opening::status),
        }
    }
    open(target, None, cancel).await.map_err(Opening::status)
}

/// A connect that failed: before the handshake, or in it.
#[derive(Debug)]
enum Opening {
    Failed(Status),
    Ssh(russh::Error),
}

impl Opening {
    fn status(self) -> Status {
        match self {
            Self::Failed(s) => s,
            Self::Ssh(e) => handshake_failure(&e),
        }
    }
}

/// The status of a failed handshake.
#[must_use]
pub fn handshake_failure(e: &russh::Error) -> Status {
    if let Some((list, offered)) = policy::no_common_algorithm(e) {
        // What the server offers in the message itself: it tells the user
        // what the server lacks (S-2).
        return Status::new(
            ErrorName::SecurityPolicy,
            format!(
                "The server offers no {list} algorithm this app accepts (it offers {})",
                offer_text(&offered)
            ),
        );
    }
    match e {
        russh::Error::Disconnect | russh::Error::HUP | russh::Error::IO(_) => {
            Status::new(ErrorName::NetworkUnreachable, "The server closed the connection")
                .with_detail(e.to_string())
        }
        _ => Status::new(ErrorName::ProtocolError, "The SSH handshake failed").with_detail(e.to_string()),
    }
}

/// The longest list of the server's algorithm names a message quotes.
const MAX_OFFER_TEXT: usize = 512;

/// The server's names, comma-separated; whole names only, up to
/// [`MAX_OFFER_TEXT`] bytes, and "…" when some are left out.
fn offer_text(offered: &[String]) -> String {
    let mut text = String::new();
    for name in offered {
        let separator = if text.is_empty() { "" } else { ", " };
        if text.len().saturating_add(separator.len()).saturating_add(name.len()) > MAX_OFFER_TEXT {
            text.push_str(if text.is_empty() { "…" } else { ", …" });
            break;
        }
        text.push_str(separator);
        text.push_str(name);
    }
    text
}

async fn open(
    target: &Target,
    pinned: Option<&russh::keys::Algorithm>,
    cancel: &CancelToken,
) -> Result<Session, Opening> {
    // Dropped on cancel or timeout: the guard in it cuts the stream, which
    // ends the session task the handshake started.
    let work = async {
        let stream = tcp(target).await.map_err(Opening::Failed)?;
        let (stream, cut) = Cuttable::new(stream);
        let guard = CutOnDrop(Some(cut.clone()));
        let seen = Shared::default();
        let config = Arc::new(policy::config(pinned));
        let handle = client::connect_stream(config, stream, Recorder { seen: seen.clone() })
            .await
            .map_err(Opening::Ssh)?;
        let key = seen.lock().host_key.clone();
        let Some(key) = key else {
            return Err(Opening::Failed(Status::new(
                ErrorName::ProtocolError,
                "The server presented no host key",
            )));
        };
        guard.disarm();
        Ok(Session { handle, seen, cut, identity: identity_of(&key) })
    };
    if cancel.is_canceled() {
        return Err(Opening::Failed(Status::canceled()));
    }
    tokio::select! {
        biased;
        () = cancel.canceled() => Err(Opening::Failed(Status::canceled())),
        result = tokio::time::timeout(target.connect_timeout, work) => {
            result.unwrap_or_else(|_| Err(Opening::Failed(timed_out(target.connect_timeout.as_millis()))))
        }
    }
}

/// The TCP connection: every address of the host in turn.
async fn tcp(target: &Target) -> Result<TcpStream, Status> {
    let unreachable = |what: String, e: &io::Error| {
        Status::new(ErrorName::NetworkUnreachable, what).with_detail(e.to_string())
    };
    let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| unreachable(format!("Cannot find the server {}", target.host), &e))?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, "the name has no address");
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                // Small requests (keep-alive, metadata) go out at once.
                drop(stream.set_nodelay(true));
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(unreachable(format!("Cannot connect to {} port {}", target.host, target.port), &last))
}

impl Session {
    /// The server's identity (S-6).
    #[must_use]
    pub const fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    /// Why the session ended, once it has.
    #[must_use]
    pub fn end(&self) -> Option<End> {
        self.seen.lock().end.clone()
    }

    /// Whether the session task has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed() || self.cut.is_cut()
    }

    /// The russh handle, for signing in.
    pub(crate) const fn handle(&mut self) -> &mut Handle<Recorder> {
        &mut self.handle
    }

    /// The status for a russh call that failed on this session: the end
    /// of the session if it ended, else `ProtocolError`.
    #[must_use]
    pub fn failure(&self, e: &russh::Error) -> Status {
        if let Some(end) = self.end() {
            return end.status();
        }
        match e {
            russh::Error::SendError
            | russh::Error::RecvError
            | russh::Error::Disconnect
            | russh::Error::HUP => connection_lost().with_detail(e.to_string()),
            _ => Status::new(ErrorName::ProtocolError, "The SSH session failed").with_detail(e.to_string()),
        }
    }

    /// XS-12: `keepalive@openssh.com` with want-reply; any answer, a
    /// refusal too (OpenSSH refuses it), proves the connection.
    ///
    /// # Errors
    /// `ConnectionLost`, `Timeout`, `Canceled`.
    pub async fn keep_alive(&self, timeout: Duration, cancel: &CancelToken) -> Result<(), Status> {
        if self.is_closed() {
            return Err(self.end().map_or_else(connection_lost, |e| e.status()));
        }
        let ask = async {
            match self.handle.send_global_request(KEEPALIVE, &[], true).await {
                Ok(_) | Err(russh::Error::RequestDenied) => Ok(()),
                Err(e) => Err(self.failure(&e)),
            }
        };
        match bounded(ask, timeout, cancel).await {
            Err(s) if s.name == ErrorName::Timeout => {
                Err(Status::new(ErrorName::Timeout, "The server did not answer the keep-alive request"))
            }
            other => other,
        }
    }

    /// Opens a session channel and starts the `sftp` subsystem on it (S-3).
    ///
    /// # Errors
    /// `TooManyConnections` (the server allows no further session),
    /// `ProtocolError` (another refusal), `Unsupported` (the subsystem is
    /// refused), `ConnectionLost`, `Timeout`, `Canceled`.
    pub async fn open_sftp(
        &self,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<(ChannelReader, ChannelWriteHalf<Msg>), Status> {
        let open = async {
            let channel = self.handle.channel_open_session().await.map_err(|e| self.channel_failure(&e))?;
            let (mut read, write) = channel.split();
            let started = async {
                write.request_subsystem(true, "sftp").await.map_err(|e| self.failure(&e))?;
                subsystem_reply(&mut read).await
            };
            match started.await {
                Ok(()) => Ok((ChannelReader::new(read), write)),
                Err(e) => {
                    drop(write.close().await);
                    Err(e)
                }
            }
        };
        bounded(open, timeout, cancel).await
    }

    /// XC-21: a refused session channel.
    fn channel_failure(&self, e: &russh::Error) -> Status {
        let russh::Error::ChannelOpenFailure(reason) = e else {
            return self.failure(e);
        };
        match reason {
            // OpenSSH refuses a session beyond MaxSessions with "connect
            // failed" (2); others say "administratively prohibited" (1) or
            // "resource shortage" (4).
            russh::ChannelOpenFailure::AdministrativelyProhibited
            | russh::ChannelOpenFailure::ConnectFailed
            | russh::ChannelOpenFailure::ResourceShortage => Status::new(
                ErrorName::TooManyConnections,
                "The server allows no further session on this connection",
            )
            .with_detail(format!("{reason:?}")),
            other => {
                Status::new(ErrorName::ProtocolError, format!("The server refused a session: {other:?}"))
            }
        }
    }

    /// Sends `DISCONNECT`, waits a moment for it to leave, cuts the stream.
    pub async fn close(mut self) {
        if !self.is_closed() {
            drop(self.handle.disconnect(Disconnect::ByApplication, "", "").await);
            drop(tokio::time::timeout(CLOSE_WAIT, &mut self.handle).await);
        }
        self.cut.cut();
    }
}

/// `Unsupported` for an account without SFTP (S-3).
#[must_use]
pub fn sftp_not_enabled() -> Status {
    Status::unsupported("SFTP is not enabled for this user")
}

/// Waits for the answer to the subsystem request.
async fn subsystem_reply(read: &mut ChannelReadHalf) -> Result<(), Status> {
    loop {
        match read.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure | ChannelMsg::Eof | ChannelMsg::Close) | None => {
                return Err(sftp_not_enabled());
            }
            Some(ChannelMsg::Data { .. }) => {
                return Err(Status::new(
                    ErrorName::ProtocolError,
                    "The server sent data before it started SFTP",
                ));
            }
            // Window adjustments, stderr text, exit status: not the answer.
            Some(_) => {}
        }
    }
}

type Wait = Pin<Box<dyn Future<Output = (ChannelReadHalf, Option<ChannelMsg>)> + Send>>;

/// The data of a channel as an owned `AsyncRead`: `EOF`, `CLOSE` or the
/// end of the session end it; an empty data message does not, and
/// extended data (stderr) is not SFTP data.
pub struct ChannelReader {
    state: Reading,
    data: Vec<u8>,
    at: usize,
}

enum Reading {
    Idle(ChannelReadHalf),
    Waiting(Wait),
    Ended,
}

impl std::fmt::Debug for ChannelReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelReader")
            .field("buffered", &self.data.len().saturating_sub(self.at))
            .finish_non_exhaustive()
    }
}

impl ChannelReader {
    /// Reads `read`.
    #[must_use]
    pub fn new(read: ChannelReadHalf) -> Self {
        Self { state: Reading::Idle(read), data: Vec::new(), at: 0 }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if let Some(rest) = this.data.get(this.at..)
                && !rest.is_empty()
            {
                let n = rest.len().min(buf.remaining());
                buf.put_slice(rest.get(..n).unwrap_or_default());
                this.at = this.at.saturating_add(n);
                return Poll::Ready(Ok(()));
            }
            let mut wait = match std::mem::replace(&mut this.state, Reading::Ended) {
                Reading::Ended => return Poll::Ready(Ok(())),
                Reading::Waiting(wait) => wait,
                Reading::Idle(mut read) => Box::pin(async move {
                    let msg = read.wait().await;
                    (read, msg)
                }),
            };
            let Poll::Ready((read, msg)) = wait.as_mut().poll(cx) else {
                this.state = Reading::Waiting(wait);
                return Poll::Pending;
            };
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    this.data = data.to_vec();
                    this.at = 0;
                    this.state = Reading::Idle(read);
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => {}
                Some(_) => this.state = Reading::Idle(read),
            }
        }
    }
}

#[cfg(test)]
mod tests;
