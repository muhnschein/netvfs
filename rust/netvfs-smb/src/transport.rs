// SPDX-License-Identifier: LGPL-2.1-or-later
//! Direct TCP transport (MS-SMB2 2.1): every message goes in a frame of a
//! zero byte, a 24-bit big-endian length and the message. A received
//! length is checked against the current cap before anything is allocated
//! (design §3.2).

use std::net::SocketAddr;
use std::time::Duration;

use netvfs_vfs::{ErrorName, Status};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result, protocol};

/// Largest frame the format can express.
pub const MAX_FRAME_FORMAT: usize = 0x00FF_FFFF;
/// The receive cap until NEGOTIATE has told the server's sizes: enough for
/// a NEGOTIATE response and SESSION_SETUP tokens.
pub const INITIAL_MAX_FRAME: usize = 64 * 1024;
/// The SMB port.
pub const DEFAULT_PORT: u16 = 445;

/// The addresses of `host` (C-17: the reason names no host).
///
/// # Errors
/// `NetworkUnreachable` when the name does not resolve.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let unresolved = |why: &str| {
        Error::Local(Status::new(
            ErrorName::NetworkUnreachable,
            format!("Cannot resolve the server name: {why}"),
        ))
    };
    let found = tokio::net::lookup_host((host, port)).await.map_err(|e| unresolved(&e.kind().to_string()))?;
    let addrs: Vec<SocketAddr> = found.collect();
    if addrs.is_empty() {
        return Err(unresolved("no address"));
    }
    Ok(addrs)
}

/// A TCP connection to the first of `addrs` that answers within `timeout`
/// in all.
///
/// # Errors
/// [`Error::Timeout`] when the time is up, else [`Error::Unreachable`] with
/// the last failure.
pub async fn connect(addrs: &[SocketAddr], timeout: Duration) -> Result<(TcpStream, SocketAddr)> {
    let attempt = async {
        let mut last = Error::Unreachable("no address".into());
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    // Small requests go out at once; nothing waits for a full segment.
                    stream.set_nodelay(true).map_err(|e| Error::Unreachable(e.to_string()))?;
                    return Ok((stream, *addr));
                }
                Err(e) => last = Error::Unreachable(e.to_string()),
            }
        }
        Err(last)
    };
    tokio::time::timeout(timeout, attempt).await.map_err(|_elapsed| Error::Timeout)?
}

/// `msg` in a frame.
///
/// # Errors
/// A message longer than the format allows.
pub fn frame(msg: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(msg.len())
        .ok()
        .filter(|l| *l <= 0x00FF_FFFF)
        .ok_or_else(|| protocol("message too long for the transport"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(msg);
    Ok(out)
}

/// Reads one frame of at most `max` bytes.
///
/// # Errors
/// [`Error::Lost`] at the end of the stream or on a socket error; a
/// protocol error for a first byte other than zero or a length above `max`.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(|e| lost(&e))?;
    let [zero, a, b, c] = head;
    if zero != 0 {
        return Err(protocol("transport header: the first byte is not zero"));
    }
    let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
    if len > max {
        return Err(protocol(format!("a frame of {len} bytes, above the cap of {max}")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| lost(&e))?;
    Ok(buf)
}

/// A socket failure.
fn lost(e: &std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Lost("the server closed the connection".into())
    } else {
        Error::Lost(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let addrs = [addr];
        let (client, server) = tokio::join!(connect(&addrs, Duration::from_secs(5)), listener.accept());
        let (client, at) = client.unwrap();
        assert_eq!(at, addr);
        (client, server.unwrap().0)
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let (mut client, mut peer) = pair().await;
        client.write_all(&frame(b"abc").unwrap()).await.unwrap();
        let mut got = [0u8; 7];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, &[0, 0, 0, 3, b'a', b'b', b'c']);
        peer.write_all(&[0, 0, 0, 2, b'x', b'y', 0, 0, 0, 0]).await.unwrap();
        assert_eq!(read_frame(&mut client, 2).await.unwrap(), b"xy");
        assert_eq!(read_frame(&mut client, 0).await.unwrap(), b"");
    }

    #[test]
    fn frame_lengths() {
        assert_eq!(frame(&vec![7u8; 0x0001_0203]).unwrap()[..4], [0, 1, 2, 3]);
        assert_eq!(frame(&vec![0u8; MAX_FRAME_FORMAT]).unwrap().len(), MAX_FRAME_FORMAT + 4);
        frame(&vec![0u8; MAX_FRAME_FORMAT + 1]).unwrap_err();
    }

    #[tokio::test]
    async fn length_above_the_cap_is_refused_before_allocation() {
        let (mut client, mut peer) = pair().await;
        // 16 MiB - 1 claimed, nothing sent after the header.
        peer.write_all(&[0, 0xff, 0xff, 0xff]).await.unwrap();
        let e = read_frame(&mut client, 1000).await.unwrap_err();
        assert!(matches!(e, Error::Protocol(ref m) if m.contains("16777215")), "{e}");
        let (mut client, mut peer) = pair().await;
        peer.write_all(&[0, 0, 0x03, 0xe9]).await.unwrap();
        assert!(matches!(read_frame(&mut client, 1000).await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn nonzero_type_byte_and_eof() {
        let (mut client, mut peer) = pair().await;
        peer.write_all(&[0x85, 0, 0, 0]).await.unwrap();
        assert!(matches!(read_frame(&mut client, 10).await, Err(Error::Protocol(_))));
        let (mut client, peer) = pair().await;
        drop(peer);
        let e = read_frame(&mut client, 10).await.unwrap_err();
        assert_eq!(e, Error::Lost("the server closed the connection".into()));
        let (mut client, mut peer) = pair().await;
        peer.write_all(&[0, 0, 0, 5, 1]).await.unwrap();
        drop(peer);
        assert!(matches!(read_frame(&mut client, 10).await, Err(Error::Lost(_))));
    }

    #[tokio::test]
    async fn connect_failures() {
        // A port nothing listens on: bind, learn the port, close.
        let addr = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let e = connect(&[addr], Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(e, Error::Unreachable(_)), "{e}");
        let e = connect(&[], Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(e, Error::Unreachable("no address".into()));
        assert_eq!(resolve("127.0.0.1", 445).await.unwrap(), ["127.0.0.1:445".parse().unwrap()]);
        // RFC 6761: .invalid never resolves.
        let e = resolve("netvfs-test.invalid", 445).await.unwrap_err().status("", crate::error::Phase::Setup);
        assert_eq!(e.name, ErrorName::NetworkUnreachable);
        assert!(e.message.starts_with("Cannot resolve the server name: "), "{e:?}");
        assert!(!e.message.contains("netvfs-test"), "{e:?}");
    }
}
