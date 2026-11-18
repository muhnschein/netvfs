// SPDX-License-Identifier: LGPL-2.1-or-later
//! One HTTP/1.1 connection over TLS, reopened when the server closes it. Each reopening is a new TLS
//! handshake that must pass the identity settled at connect (`netvfs_tls::Client`).

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, USER_AGENT};
use http::{HeaderName, HeaderValue, Method, Request, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use hyper::body::Incoming;
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use netvfs_tls::Client as Tls;
use netvfs_vfs::{ErrorName, Status};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::paths::encode;

/// Default of [`Target::stale_after`].
pub const STALE_AFTER: Duration = Duration::from_secs(1);
/// HTTP/1.1 for ALPN.
pub const ALPN: &[u8] = b"http/1.1";
const AGENT: &str = concat!("netvfs/", env!("CARGO_PKG_VERSION"));

/// A request body.
#[derive(Debug)]
pub enum Body {
    /// None.
    Empty,
    /// These bytes; `None` once sent.
    Full(Option<Bytes>),
    /// Chunks from a channel, with the total when known.
    Stream(mpsc::Receiver<Bytes>, Option<u64>),
}

impl Body {
    /// Whether it can be sent again after a failed attempt.
    const fn replayable(&self) -> bool {
        !matches!(self, Self::Stream(..))
    }

    /// A copy for one attempt; a stream moves.
    fn take(&mut self) -> Self {
        match self {
            Self::Empty => Self::Empty,
            Self::Full(b) => Self::Full(b.clone()),
            Self::Stream(..) => std::mem::replace(self, Self::Empty),
        }
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match &mut *self {
            Self::Empty => Poll::Ready(None),
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream(rx, _) => rx.poll_recv(cx).map(|c| c.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(b) => b.is_none(),
            Self::Stream(..) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Self::Stream(_, Some(n)) => SizeHint::with_exact(*n),
            Self::Stream(_, None) => SizeHint::default(),
        }
    }
}

/// One request: method, decoded server path, extra headers, body.
#[derive(Debug)]
pub struct Req {
    /// The method.
    pub method: Method,
    /// The decoded server path.
    pub path: Vec<u8>,
    /// More headers.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// The body.
    pub body: Body,
}

impl Req {
    /// `method` on `path`, no body.
    #[must_use]
    pub const fn new(method: Method, path: Vec<u8>) -> Self {
        Self { method, path, headers: Vec::new(), body: Body::Empty }
    }

    /// With a header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// With `body`.
    #[must_use]
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }
}

/// Where to connect and how long to wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or address (IPv6 without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Bound of TCP connect plus TLS handshake.
    pub connect_timeout: Duration,
    /// Bound of each wait for the server: answer head, each body chunk.
    pub request_timeout: Duration,
    /// A connection idle this long is reopened before a body that cannot be sent twice.
    pub stale_after: Duration,
}

impl Target {
    /// `host[:port]` for `Host`, brackets around IPv6, no port for 443.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == 443 { host } else { format!("{host}:{}", self.port) }
    }
}

#[derive(Debug)]
struct Conn {
    sender: SendRequest<Body>,
    /// A request was sent whose answer was not read to the end.
    busy: bool,
    idle_since: Instant,
}

/// The connection.
#[derive(Debug)]
pub struct Http {
    tls: Tls,
    target: Target,
    host: HeaderValue,
    auth: Option<HeaderValue>,
    conn: Option<Conn>,
    ended: bool,
}

/// A dropped connection.
#[must_use]
pub fn lost(detail: impl Into<String>) -> Status {
    Status::new(ErrorName::ConnectionLost, "The connection to the server dropped").with_detail(detail)
}

/// Whether `e` says the server closed the connection before answering: a reused connection that went stale.
fn dropped_unanswered(e: &hyper::Error) -> bool {
    if e.is_canceled() || e.is_closed() || e.is_incomplete_message() {
        return true;
    }
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            );
        }
        source = s.source();
    }
    false
}

fn timed_out() -> Status {
    Status::new(ErrorName::Timeout, "The server did not answer in time")
}

impl Http {
    /// Unconnected.
    ///
    /// # Errors
    /// `InvalidName` for a host that does not fit in `Host`.
    pub fn new(tls: Tls, target: Target) -> Result<Self, Status> {
        let host = HeaderValue::from_str(&target.authority())
            .map_err(|_bad| Status::invalid_name(format!("Not a host name: {}", target.host)))?;
        Ok(Self { tls, target, host, auth: None, conn: None, ended: false })
    }

    /// The TLS side.
    #[must_use]
    pub const fn tls(&self) -> &Tls {
        &self.tls
    }

    /// The target.
    #[must_use]
    pub const fn target(&self) -> &Target {
        &self.target
    }

    /// `https://authority`, for `Destination`.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("https://{}", self.target.authority())
    }

    /// Sets the `Authorization` value of every later request.
    pub fn set_auth(&mut self, mut value: HeaderValue) {
        value.set_sensitive(true);
        self.auth = Some(value);
    }

    /// Opens a new connection, dropping any old one.
    ///
    /// # Errors
    /// From name lookup, TCP, TLS (`ServerIdentityChanged`, `SecurityPolicy`) and the HTTP handshake.
    pub async fn open(&mut self) -> Result<(), Status> {
        self.conn = None;
        let t = &self.target;
        let started = Instant::now();
        let addrs = netvfs_tls::resolve(&t.host, t.port).await?;
        let tcp = netvfs_tls::connect_tcp(&addrs, t.connect_timeout).await?;
        let left = t.connect_timeout.saturating_sub(started.elapsed());
        let tls = self.tls.handshake(tcp, left).await?;
        let (sender, conn) = http1::handshake(TokioIo::new(tls)).await.map_err(|e| lost(e.to_string()))?;
        // Ends when the server closes, or once `sender` and any answer body are dropped.
        tokio::spawn(async move { drop(conn.await) });
        self.conn = Some(Conn { sender, busy: false, idle_since: Instant::now() });
        Ok(())
    }

    /// Drops the connection.
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// Drops the connection for good: later requests are `ConnectionLost`.
    pub fn end(&mut self) {
        self.conn = None;
        self.ended = true;
    }

    /// The answer was read to the end: the connection may carry the next request.
    pub fn done(&mut self) {
        if let Some(c) = &mut self.conn {
            c.busy = false;
            c.idle_since = Instant::now();
        }
    }

    fn usable(&self, fresh_for_stream: bool) -> bool {
        self.conn.as_ref().is_some_and(|c| {
            !c.busy
                && !c.sender.is_closed()
                && (!fresh_for_stream || c.idle_since.elapsed() < self.target.stale_after)
        })
    }

    fn build(&self, req: &mut Req) -> Result<Request<Body>, Status> {
        let mut b = Request::builder().method(req.method.clone()).uri(encode(&req.path));
        b = b.header(HOST, self.host.clone()).header(USER_AGENT, HeaderValue::from_static(AGENT));
        if let Some(auth) = &self.auth {
            b = b.header(AUTHORIZATION, auth.clone());
        }
        if matches!(req.body, Body::Empty) && !matches!(req.method, Method::GET | Method::OPTIONS) {
            b = b.header(CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        for (name, value) in &req.headers {
            b = b.header(name, value);
        }
        b.body(req.body.take()).map_err(|e| Status::internal(format!("Cannot build the request: {e}")))
    }

    /// Sends `req` and returns the answer head; the body is the caller's to read, then [`done`](Self::done).
    /// A request that fails on a reused connection before any answer is sent once more on a new one when its
    /// body allows.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`, and what [`open`](Self::open) gives.
    pub async fn send(&mut self, mut req: Req) -> Result<Response<Incoming>, Status> {
        if self.ended {
            return Err(lost("the connection was closed"));
        }
        let replayable = req.body.replayable();
        let mut fresh = !self.usable(!replayable);
        if fresh {
            self.open().await?;
        }
        loop {
            let request = self.build(&mut req)?;
            let timeout = self.target.request_timeout;
            let conn = self.conn.as_mut().ok_or_else(|| lost("no connection"))?;
            conn.busy = true;
            let sent = tokio::time::timeout(timeout, async {
                conn.sender.ready().await?;
                conn.sender.send_request(request).await
            })
            .await;
            match sent {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e)) if !fresh && replayable && dropped_unanswered(&e) => {
                    self.open().await?;
                    fresh = true;
                }
                Ok(Err(e)) => {
                    self.conn = None;
                    return Err(lost(e.to_string()));
                }
                Err(_elapsed) => {
                    self.conn = None;
                    return Err(timed_out());
                }
            }
        }
    }

    /// The next chunk of `body`, `None` at its end, each within the request timeout.
    ///
    /// # Errors
    /// `Timeout`, `ConnectionLost`; the connection is dropped.
    pub async fn chunk(&mut self, body: &mut Incoming) -> Result<Option<Bytes>, Status> {
        use http_body_util::BodyExt;
        loop {
            let frame = tokio::time::timeout(self.target.request_timeout, body.frame()).await;
            match frame {
                Ok(None) => return Ok(None),
                Ok(Some(Ok(f))) => {
                    if let Ok(data) = f.into_data() {
                        return Ok(Some(data));
                    }
                }
                Ok(Some(Err(e))) => {
                    self.conn = None;
                    return Err(lost(e.to_string()));
                }
                Err(_elapsed) => {
                    self.conn = None;
                    return Err(timed_out());
                }
            }
        }
    }

    /// The whole body, at most `cap` bytes, then [`done`](Self::done).
    ///
    /// # Errors
    /// `ProtocolError` above `cap`; what [`chunk`](Self::chunk) gives.
    pub async fn read_all(&mut self, mut body: Incoming, cap: usize) -> Result<Vec<u8>, Status> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk(&mut body).await? {
            if out.len().saturating_add(chunk.len()) > cap {
                self.conn = None;
                return Err(Status::new(ErrorName::ProtocolError, "The server's answer is too large")
                    .with_detail(format!("more than {cap} bytes")));
            }
            out.extend_from_slice(&chunk);
        }
        self.done();
        Ok(out)
    }

    /// Reads and drops the body (an error page, say) up to `cap`; drops the connection beyond.
    pub async fn discard(&mut self, mut body: Incoming, cap: usize) {
        let mut seen = 0usize;
        loop {
            match self.chunk(&mut body).await {
                Ok(Some(c)) => {
                    seen = seen.saturating_add(c.len());
                    if seen > cap {
                        self.conn = None;
                        return;
                    }
                }
                Ok(None) => {
                    self.done();
                    return;
                }
                Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests;
