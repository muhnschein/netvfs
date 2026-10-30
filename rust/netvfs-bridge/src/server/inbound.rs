// SPDX-License-Identifier: LGPL-2.1-or-later
//! Read half of a session's socket: zbus accepts messages up to 128 MiB and queues up to `max_queued`, so the bridge reads frames itself and closes the connection on a header declaring more than [`MAX_MESSAGE_BYTES`] (before the body is read) or more than [`MAX_MESSAGE_FDS`] descriptors.
//!
//! Largest legitimate call: `ConnectAdHoc` (64 KiB secret, 4 KiB URL); `Upload` and `Download` carry one descriptor.

use crate::sys::frame::message_from_frame;
use std::future::Future;
use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use zbus::Message;
use zbus::connection::socket::ReadHalf;
use zbus::fdo::ConnectionCredentials;
use zbus::zvariant::Endian;

/// Largest message a consumer may send.
pub const MAX_MESSAGE_BYTES: usize = 2 << 20;
/// Most descriptors one message may carry.
pub const MAX_MESSAGE_FDS: usize = 2;
const PRIMARY_HEADER_BYTES: usize = 16;

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the primary header says about a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSize {
    /// Byte order of the message.
    pub endian: Endian,
    /// Header, padding and body.
    pub total: u64,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Reads the primary header: endianness byte, body length (bytes 4..8) and
/// the length of the header fields array (bytes 12..16).
///
/// # Errors
/// An unknown endianness byte or fewer than 16 bytes.
pub fn frame_size(header: &[u8]) -> io::Result<FrameSize> {
    let field = |at: usize| -> io::Result<[u8; 4]> {
        header
            .get(at..at.saturating_add(4))
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid("short header"))
    };
    let (endian, read): (Endian, fn([u8; 4]) -> u32) = match header.first() {
        Some(b'l') => (Endian::Little, u32::from_le_bytes),
        Some(b'B') => (Endian::Big, u32::from_be_bytes),
        _ => return Err(invalid("not a D-Bus message")),
    };
    let body = u64::from(read(field(4)?));
    let fields = u64::from(read(field(12)?));
    // The header is padded to 8 bytes before the body.
    let padded = fields.saturating_add(16).next_multiple_of(8);
    Ok(FrameSize { endian, total: padded.saturating_add(body) })
}

/// A read half that refuses oversized messages.
#[derive(Debug)]
pub struct LimitedRead {
    inner: Box<dyn ReadHalf>,
}

impl LimitedRead {
    /// Wraps the read half of a connection.
    #[must_use]
    pub fn new(inner: Box<dyn ReadHalf>) -> Self {
        Self { inner }
    }

    async fn fill(&mut self, bytes: &mut Vec<u8>, want: usize, fds: &mut Vec<OwnedFd>) -> zbus::Result<()> {
        while bytes.len() < want {
            let start = bytes.len();
            bytes.resize(want, 0);
            let rest = bytes.get_mut(start..).unwrap_or_default();
            let (n, received) = self.inner.recvmsg(rest).await?;
            bytes.truncate(start.saturating_add(n));
            fds.extend(received);
            if fds.len() > MAX_MESSAGE_FDS {
                return Err(invalid("too many descriptors in one message").into());
            }
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed").into());
            }
        }
        Ok(())
    }

    async fn read_message(
        &mut self,
        carried: &mut Vec<u8>,
        carried_fds: &mut Vec<OwnedFd>,
    ) -> zbus::Result<Message> {
        let mut fds: Vec<OwnedFd> = std::mem::take(carried_fds);
        let mut bytes: Vec<u8> = carried.drain(..carried.len().min(PRIMARY_HEADER_BYTES)).collect();
        self.fill(&mut bytes, PRIMARY_HEADER_BYTES, &mut fds).await?;
        let size = frame_size(&bytes)?;
        let total = usize::try_from(size.total).ok().filter(|t| *t <= MAX_MESSAGE_BYTES);
        let Some(total) = total else {
            return Err(invalid("message larger than 2 MiB").into());
        };
        let from_carried = total.saturating_sub(bytes.len()).min(carried.len());
        bytes.extend(carried.drain(..from_carried));
        self.fill(&mut bytes, total, &mut fds).await?;
        message_from_frame(bytes, fds, size.endian)
    }
}

impl ReadHalf for LimitedRead {
    fn receive_message<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 mut self,
        _seq: u64,
        already_received_bytes: &'life1 mut Vec<u8>,
        already_received_fds: &'life2 mut Vec<OwnedFd>,
    ) -> Boxed<'async_trait, zbus::Result<Message>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.read_message(already_received_bytes, already_received_fds))
    }

    fn recvmsg<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        buf: &'life1 mut [u8],
    ) -> Boxed<'async_trait, io::Result<(usize, Vec<OwnedFd>)>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.recvmsg(buf)
    }

    fn can_pass_unix_fd(&self) -> bool {
        self.inner.can_pass_unix_fd()
    }

    fn peer_credentials<'life0, 'async_trait>(
        &'life0 mut self,
    ) -> Boxed<'async_trait, io::Result<ConnectionCredentials>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.peer_credentials()
    }

    fn auth_mechanism(&self) -> zbus::AuthMechanism {
        self.inner.auth_mechanism()
    }
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;
