// SPDX-License-Identifier: LGPL-2.1-or-later
//! Client side of the peer-to-peer connection (SPEC-v2 XB-3): a unix socket
//! with fd passing and no bus daemon.

use crate::errors::BridgeError;
use crate::proxy::Bridge1Proxy;
use crate::signals::{Signal, decode_signal};
use crate::wire::Opts;
use futures_lite::{Stream, StreamExt as _};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

/// A connected bridge: the zbus connection and its proxy.
#[derive(Clone)]
pub struct Connection {
    conn: zbus::Connection,
    proxy: Bridge1Proxy<'static>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Connection")
    }
}

/// Connects to the bridge socket.
///
/// # Errors
/// [`BridgeError::Disconnected`] when the socket cannot be reached or the
/// handshake fails.
pub async fn connect(socket_path: &Path) -> Result<Connection, BridgeError> {
    let stream = UnixStream::connect(socket_path).await?;
    Connection::from_stream(stream).await
}

impl Connection {
    /// Runs the (peer-to-peer) client handshake over an already connected
    /// stream. Used by [`connect`] and by the fake bridge.
    ///
    /// # Errors
    /// [`BridgeError::Disconnected`] when the handshake fails.
    pub async fn from_stream(stream: UnixStream) -> Result<Self, BridgeError> {
        let conn = zbus::connection::Builder::unix_stream(stream).p2p().build().await?;
        let proxy = Bridge1Proxy::builder(&conn).build().await?;
        Ok(Self { conn, proxy })
    }

    /// The `org.netvfs.Bridge1` proxy.
    #[must_use]
    pub fn proxy(&self) -> &Bridge1Proxy<'static> {
        &self.proxy
    }

    /// The underlying zbus connection.
    pub fn zbus(&self) -> &zbus::Connection {
        &self.conn
    }

    /// Closes the socket; calls and signals end with a disconnect.
    pub async fn close(&self) {
        // Closing an already closed connection is not an error worth reporting.
        self.conn.clone().close().await.ok();
    }

    /// All signals in arrival order. The stream ends when the socket closes.
    /// Create it before the first call so that no signal is missed.
    #[must_use]
    pub fn signals(&self) -> SignalStream {
        SignalStream { inner: zbus::MessageStream::from(&self.conn), done: false }
    }

    /// `ConnectAdHoc` that wipes `secret` before returning, also when the call
    /// fails or the future is dropped (SPEC-v2 XB-16). The secret is passed
    /// as `ay`; the copy that zbus serialises into the outgoing message lives
    /// in the message buffer until it has been sent.
    ///
    /// # Errors
    /// The bridge's refusal, or a broken connection.
    pub async fn connect_ad_hoc_wiping(
        &self,
        url: &str,
        secret: &mut Zeroizing<Vec<u8>>,
        opts: &Opts,
    ) -> Result<String, BridgeError> {
        let guard = WipeOnDrop(secret);
        let result = self.proxy.connect_ad_hoc(url, guard.0.as_slice(), opts).await;
        drop(guard);
        result.map_err(BridgeError::from)
    }

    /// `Answer` whose keyboard-interactive `answers` are wiped afterwards.
    ///
    /// # Errors
    /// The bridge's refusal, or a broken connection.
    pub async fn answer_wiping(
        &self,
        id: &str,
        accept: bool,
        answers: &mut Zeroizing<Vec<Vec<u8>>>,
    ) -> Result<(), BridgeError> {
        let mut builder = crate::wire::OptsBuilder::new().bool("accept", accept);
        if !answers.is_empty() {
            builder = builder.byte_arrays("answers", answers);
        }
        let opts = builder.build();
        let result = self.proxy.answer(id, &opts).await;
        for a in answers.iter_mut() {
            a.zeroize();
        }
        answers.clear();
        result.map_err(BridgeError::from)
    }
}

struct WipeOnDrop<'a>(&'a mut Zeroizing<Vec<u8>>);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ordered stream of decoded signals.
#[derive(Debug)]
pub struct SignalStream {
    inner: zbus::MessageStream,
    done: bool,
}

impl Stream for SignalStream {
    type Item = Result<Signal, BridgeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            match self.inner.poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.done = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(e))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(BridgeError::from(e))));
                }
                Poll::Ready(Some(Ok(msg))) => match decode_signal(&msg) {
                    Ok(Some(signal)) => return Poll::Ready(Some(Ok(signal))),
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Some(Err(e))),
                },
            }
        }
    }
}
