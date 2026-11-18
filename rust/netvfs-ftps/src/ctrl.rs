// SPDX-License-Identifier: LGPL-2.1-or-later
//! The control connection (explicit TLS: `AUTH TLS` on the plain greeting, RFC 4217) and its protected data
//! connections (`EPSV`, RFC 2428; TLS 1.3, resuming the control connection's session as servers demand).

use crate::reply::{self, Reply, lost};
use netvfs_tls::{Client as Tls, TlsStream};
use netvfs_vfs::{CancelToken, ErrorName, Status};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Name or address, no brackets.
    pub host: String,
    /// Control port.
    pub port: u16,
    /// For TCP and TLS set-up.
    pub connect_timeout: Duration,
    /// For each reply and each data read or write.
    pub request_timeout: Duration,
}

/// A protected data connection.
pub type Data = TlsStream<TcpStream>;

/// A path argument: protocol bytes without line breaks, NUL or Telnet IAC; empty is `/`.
///
/// # Errors
/// `InvalidName` for a byte a command line cannot carry.
pub fn arg(path: &[u8]) -> Result<&[u8], Status> {
    if path.iter().any(|b| matches!(b, b'\r' | b'\n' | 0 | 0xff)) {
        return Err(Status::invalid_name("FTP cannot carry this name"));
    }
    Ok(if path.is_empty() { b"/" } else { path })
}

async fn timed<T>(
    limit: Duration,
    what: &str,
    work: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    tokio::time::timeout(limit, work).await.map_err(|_elapsed| {
        Status::new(ErrorName::Timeout, format!("The server did not answer in time ({what})"))
    })?
}

async fn send(w: &mut (impl AsyncWrite + Unpin), line: &[u8]) -> Result<(), Status> {
    let mut out = Vec::with_capacity(line.len().saturating_add(2));
    out.extend_from_slice(line);
    out.extend_from_slice(b"\r\n");
    w.write_all(&out).await.map_err(|e| lost(&e.to_string()))?;
    w.flush().await.map_err(|e| lost(&e.to_string()))
}

/// The greeting: preliminary 120 replies skipped, then 220.
async fn greeting(r: &mut (impl AsyncBufRead + Unpin)) -> Result<(), Status> {
    loop {
        let r = reply::read(r).await?;
        match r.code {
            120 => {}
            220 => return Ok(()),
            _ => return Err(reply::error(&r, "Connecting")),
        }
    }
}

/// A signed-out control connection, TLS from `AUTH TLS` on.
#[derive(Debug)]
pub struct Session {
    ctrl: BufReader<Data>,
    tls: Tls,
    peer: IpAddr,
    target: Target,
    /// Replies the server owes: a call canceled or timed out before reading them. The next command reads them first.
    pending: u32,
    /// A command line partly sent, a reply partly read, or 421: the connection cannot be used.
    torn: bool,
}

impl Session {
    /// Connects, reads the greeting, switches to TLS.
    ///
    /// # Errors
    /// Network and TLS errors; `SecurityPolicy` when the server refuses `AUTH TLS`.
    pub async fn open(tls: Tls, target: Target) -> Result<Self, Status> {
        let addrs = netvfs_tls::resolve(&target.host, target.port).await?;
        let tcp = netvfs_tls::connect_tcp(&addrs, target.connect_timeout).await?;
        let peer = tcp.peer_addr().map_err(|e| lost(&e.to_string()))?.ip();
        let mut plain = BufReader::new(tcp);
        timed(target.request_timeout, "greeting", greeting(&mut plain)).await?;
        send(plain.get_mut(), b"AUTH TLS").await?;
        let auth = timed(target.request_timeout, "AUTH TLS", reply::read(&mut plain)).await?;
        if auth.code != 234 {
            return Err(Status::new(ErrorName::SecurityPolicy, "The server does not offer FTP over TLS")
                .with_detail(auth.text()));
        }
        if !plain.buffer().is_empty() {
            return Err(Status::new(
                ErrorName::ProtocolError,
                "The server sent data before the TLS handshake",
            ));
        }
        let stream = tls.handshake(plain.into_inner(), target.connect_timeout).await?;
        Ok(Self { ctrl: BufReader::new(stream), tls, peer, target, pending: 0, torn: false })
    }

    /// The TLS client: its last certificate and pin policy.
    #[must_use]
    pub const fn tls(&self) -> &Tls {
        &self.tls
    }

    /// Sends `line`, returns the reply.
    ///
    /// # Errors
    /// `ConnectionLost` on a torn or failed connection; `Timeout`; reply errors.
    pub async fn cmd(&mut self, line: &[u8]) -> Result<Reply, Status> {
        while self.pending > 0 {
            self.next().await?;
        }
        if self.torn {
            return Err(lost("an earlier command did not finish"));
        }
        self.torn = true;
        send(self.ctrl.get_mut(), line).await?;
        self.torn = false;
        self.pending = 1;
        self.next().await
    }

    /// `cmd`, then any code but `ok` is the error of `what`.
    ///
    /// # Errors
    /// As `cmd`; the reply's error.
    pub async fn expect(&mut self, line: &[u8], ok: &[u16], what: &str) -> Result<Reply, Status> {
        let r = self.cmd(line).await?;
        if ok.contains(&r.code) { Ok(r) } else { Err(reply::error(&r, what)) }
    }

    /// The next reply owed.
    async fn next(&mut self) -> Result<Reply, Status> {
        if self.torn {
            return Err(lost("an earlier command did not finish"));
        }
        self.torn = true;
        let r = timed(self.target.request_timeout, "reply", reply::read(&mut self.ctrl)).await?;
        self.torn = r.code == 421;
        if r.class() != 1 {
            self.pending = self.pending.saturating_sub(1);
        }
        Ok(r)
    }

    /// A data connection for `line` (`MLSD`, `RETR`, `STOR`): `EPSV`, TCP, `line`, its preliminary reply, TLS.
    ///
    /// # Errors
    /// `Unsupported` without `EPSV`; network and TLS errors; the reply's error of `what`.
    pub async fn data(&mut self, line: &[u8], what: &str) -> Result<Data, Status> {
        let epsv = self.cmd(b"EPSV").await?;
        if epsv.code != 229 {
            return Err(Status::unsupported("The server does not offer extended passive mode (EPSV)")
                .with_detail(epsv.text()));
        }
        let port = epsv_port(&epsv)?;
        let tcp =
            netvfs_tls::connect_tcp(&[SocketAddr::new(self.peer, port)], self.target.connect_timeout).await?;
        let started = self.cmd(line).await?;
        if started.class() != 1 {
            return Err(reply::error(&started, what));
        }
        let stream = self.tls.handshake(tcp, self.target.connect_timeout).await?;
        Ok(stream)
    }

    /// The reply ending a transfer.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`; the reply's error of `what`.
    pub async fn finish(&mut self, what: &str) -> Result<Reply, Status> {
        let r = self.next().await?;
        if r.class() == 2 { Ok(r) } else { Err(reply::error(&r, what)) }
    }

    /// Reads `data` to its end within `cap` bytes, then the reply ending the transfer.
    ///
    /// # Errors
    /// `ProtocolError` past `cap`; transfer errors.
    pub async fn read_all(&mut self, mut data: Data, cap: usize, what: &str) -> Result<Vec<u8>, Status> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = self.read(&mut data, &mut buf, &CancelToken::new()).await?;
            if n == 0 {
                break;
            }
            if out.len().saturating_add(n) > cap {
                return Err(Status::new(ErrorName::ProtocolError, format!("{what}: more than {cap} bytes")));
            }
            out.extend_from_slice(buf.get(..n).unwrap_or_default());
        }
        drop(data);
        self.finish(what).await?;
        Ok(out)
    }

    /// One read of a data connection; ends early on `cancel`.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`, `Canceled`.
    pub async fn read(&self, data: &mut Data, buf: &mut [u8], cancel: &CancelToken) -> Result<usize, Status> {
        let read = async { data.read(buf).await.map_err(|e| lost(&e.to_string())) };
        tokio::select! {
            r = timed(self.target.request_timeout, "data", read) => r,
            () = cancel.canceled() => Err(Status::canceled()),
        }
    }

    /// One write to a data connection; ends early on `cancel`.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`, `Canceled`.
    pub async fn write(&self, data: &mut Data, buf: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        let write = async { data.write_all(buf).await.map_err(|e| lost(&e.to_string())) };
        tokio::select! {
            r = timed(self.target.request_timeout, "data", write) => r,
            () = cancel.canceled() => Err(Status::canceled()),
        }
    }

    /// Stops a transfer with `ABOR` (RFC 959) and a TLS close, reads `data` until the server closes it, then the
    /// replies owed. Dropping a protected data connection instead makes some servers (proftpd) end the session.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`.
    pub async fn abort(&mut self, mut data: Data) -> Result<(), Status> {
        self.torn = true;
        send(self.ctrl.get_mut(), b"ABOR").await?;
        self.torn = false;
        self.pending = self.pending.saturating_add(1);
        let drain = async {
            drop(data.shutdown().await);
            let mut sink = vec![0u8; 64 * 1024];
            while matches!(data.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        drop(tokio::time::timeout(self.target.request_timeout, drain).await);
        drop(data);
        while self.pending > 0 {
            self.next().await?;
        }
        Ok(())
    }

    /// Ends an upload's data connection with a TLS close, so the server knows the file is whole, then waits for
    /// the server's close: closing with unread data (session tickets) resets the connection, losing the file's tail.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`.
    pub async fn close_data(&self, mut data: Data) -> Result<(), Status> {
        let shut = async {
            data.shutdown().await.map_err(|e| lost(&e.to_string()))?;
            let mut sink = [0u8; 512];
            // Some servers close without TLS close: the reply tells whether the file arrived.
            while matches!(data.read(&mut sink).await, Ok(n) if n > 0) {}
            Ok(())
        };
        timed(self.target.request_timeout, "data", shut).await
    }

    /// `QUIT`, best effort.
    pub async fn quit(mut self) {
        if !self.torn {
            let bye = async {
                send(self.ctrl.get_mut(), b"QUIT").await?;
                reply::read(&mut self.ctrl).await
            };
            drop(tokio::time::timeout(Duration::from_secs(2), bye).await);
        }
        drop(tokio::time::timeout(Duration::from_secs(2), self.ctrl.get_mut().shutdown()).await);
    }
}

/// The port of a 229 reply: `(|||port|)`, any delimiter.
///
/// # Errors
/// `ProtocolError` for anything else.
pub fn epsv_port(r: &Reply) -> Result<u16, Status> {
    let bad = || Status::new(ErrorName::ProtocolError, "Unreadable passive mode reply").with_detail(r.text());
    let text = r.lines.first().ok_or_else(bad)?;
    let open = text.iter().position(|b| *b == b'(').ok_or_else(bad)?;
    let inner = text.get(open.saturating_add(1)..).ok_or_else(bad)?;
    let close = inner.iter().position(|b| *b == b')').ok_or_else(bad)?;
    let inner = inner.get(..close).ok_or_else(bad)?;
    let d = *inner.first().ok_or_else(bad)?;
    let parts: Vec<&[u8]> = inner.split(|b| *b == d).collect();
    let [empty_a, empty_b, empty_c, port, tail] = parts.as_slice() else {
        return Err(bad());
    };
    let framed = empty_a.is_empty() && empty_b.is_empty() && empty_c.is_empty() && tail.is_empty();
    if !framed || !port.iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    let port: u16 = std::str::from_utf8(port).ok().and_then(|p| p.parse().ok()).ok_or_else(bad)?;
    if port == 0 { Err(bad()) } else { Ok(port) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r229(text: &[u8]) -> Reply {
        Reply { code: 229, lines: vec![text.to_vec()] }
    }

    #[test]
    fn passive_ports() {
        assert_eq!(epsv_port(&r229(b"Entering Extended Passive Mode (|||6446|)")), Ok(6446));
        assert_eq!(epsv_port(&r229(b"Entering (!!!65535!)")), Ok(65535));
        for bad in [
            &b"no parens"[..],
            b"(|||0|)",
            b"(|||65536|)",
            b"(||1|2|)",
            b"(|||12a|)",
            b"(||||)",
            b"(|||123456|)",
            b"(|||1||)",
            b"(|||1|",
            b"(|||+12|)",
            b"()",
        ] {
            assert_eq!(epsv_port(&r229(bad)).unwrap_err().name, ErrorName::ProtocolError, "{bad:?}");
        }
        epsv_port(&Reply { code: 229, lines: vec![] }).unwrap_err();
    }

    #[test]
    fn arguments_carry_no_line_breaks() {
        assert_eq!(arg(b"").unwrap(), b"/");
        assert_eq!(arg(b"/a b/c").unwrap(), b"/a b/c");
        for bad in [&b"/a\rb"[..], b"/a\nb", b"/a\0b", b"/a\xffb"] {
            assert_eq!(arg(bad).unwrap_err().name, ErrorName::InvalidName);
        }
    }
}
