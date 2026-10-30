// SPDX-License-Identifier: LGPL-2.1-or-later
//! Listening socket and accept loop: every connection is peer-checked on the raw descriptor before a byte is read; a refused peer is closed without a reply.
//!
//! Addresses: `systemd:` takes the socket systemd passed (`LISTEN_PID`, `LISTEN_FDS`, fd 3; the rendezvous stays the socket systemd created in the consumer's folder); `unix:path=<path>` binds a new socket (development and tests).

use super::{Event, EventSink, SessionId, session};
use crate::peer::PeerChecker;
use crate::status::Status;
use crate::sys;
use netvfs_bridge_proto::ErrorName;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Where the bridge listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddress {
    /// `systemd:`.
    Systemd,
    /// `unix:path=<path>`.
    Path(PathBuf),
}

impl ListenAddress {
    /// Parses a D-Bus server address (percent escapes in the path decoded).
    ///
    /// # Errors
    /// `NetworkUnreachable` for any other address.
    pub fn parse(address: &str) -> Result<Self, Status> {
        if address == "systemd:" {
            return Ok(Self::Systemd);
        }
        address
            .strip_prefix("unix:path=")
            .and_then(unescape)
            .filter(|p| !p.is_empty())
            .map(|p| {
                Self::Path(PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                    p,
                )))
            })
            .ok_or_else(|| Status::new(ErrorName::NetworkUnreachable, format!("Cannot listen on {address}")))
    }
}

fn unescape(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let high = hex_digit(bytes.next()?)?;
                out.push(high << 4 | hex_digit(bytes.next()?)?);
            }
            b',' | b';' => return None,
            _ => out.push(b),
        }
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

fn systemd_socket(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
) -> io::Result<std::os::unix::net::UnixListener> {
    let not_activated =
        |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("not socket-activated: {what}"));
    let pid: u32 = listen_pid.and_then(|v| v.parse().ok()).ok_or_else(|| not_activated("no LISTEN_PID"))?;
    if pid != std::process::id() {
        return Err(not_activated("LISTEN_PID is another process"));
    }
    let fds: u32 = listen_fds.and_then(|v| v.parse().ok()).ok_or_else(|| not_activated("no LISTEN_FDS"))?;
    if fds == 0 {
        return Err(not_activated("LISTEN_FDS is 0"));
    }
    sys::listen::adopt_listener(sys::listen::take_systemd_socket()?)
}

/// Opens the listening socket. Must run inside the tokio runtime.
///
/// # Errors
/// `NetworkUnreachable` "Cannot listen on …".
pub fn bind(address: &ListenAddress) -> Result<UnixListener, Status> {
    let std_listener = match address {
        ListenAddress::Systemd => systemd_socket(
            std::env::var("LISTEN_PID").ok().as_deref(),
            std::env::var("LISTEN_FDS").ok().as_deref(),
        ),
        ListenAddress::Path(path) => std::os::unix::net::UnixListener::bind(path).and_then(|l| {
            l.set_nonblocking(true)?;
            Ok(l)
        }),
    };
    std_listener
        .and_then(UnixListener::from_std)
        .map_err(|e| Status::new(ErrorName::NetworkUnreachable, format!("Cannot listen on {address:?}: {e}")))
}

/// The accept loop of one bridge.
#[derive(Debug)]
pub struct Listener {
    socket: UnixListener,
    checker: Arc<PeerChecker>,
    sink: EventSink,
    next: u64,
}

impl Listener {
    /// A listener that checks each peer with `checker` and reports to `sink`.
    #[must_use]
    pub fn new(listener: UnixListener, checker: PeerChecker, sink: EventSink) -> Self {
        Self { socket: listener, checker: Arc::new(checker), sink, next: 1 }
    }

    /// Accepts connections until the task is dropped or `accept` fails for good.
    pub async fn serve(mut self) -> io::Error {
        loop {
            match self.socket.accept().await {
                Ok((stream, _)) => {
                    let sid = SessionId(self.next);
                    self.next = self.next.saturating_add(1);
                    tokio::spawn(connection(stream, sid, Arc::clone(&self.checker), self.sink.clone()));
                }
                Err(e) if is_transient(&e) => tokio::time::sleep(ACCEPT_BACKOFF).await,
                Err(e) => return e,
            }
        }
    }
}

fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::OutOfMemory
    ) || matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EPROTO)
    )
}

async fn connection(stream: UnixStream, sid: SessionId, checker: Arc<PeerChecker>, sink: EventSink) {
    let verdict = match stream.as_fd().try_clone_to_owned() {
        Ok(probe) => tokio::task::spawn_blocking(move || checker.check(probe.as_fd()).map(|()| probe))
            .await
            .unwrap_or_else(|_| Err(Status::new(ErrorName::Internal, "the peer check failed"))),
        Err(e) => Err(Status::permission_denied(format!("no peer credentials: {e}"))),
    };
    match verdict {
        Ok(probe) => session::run(stream, StdUnixStream::from(probe), sid, sink).await,
        Err(reason) => sink.deliver(Event::Refused { reason }),
    }
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
