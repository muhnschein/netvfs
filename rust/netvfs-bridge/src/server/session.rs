// SPDX-License-Identifier: LGPL-2.1-or-later
//! One consumer connection after the peer check (design §3.2
//! `server::session`): the p2p handshake, then a reader (zbus
//! `MessageStream` → [`dispatch`] → [`Event::Call`]) and a writer
//! ([`flow::run_writer`]).
//!
//! The message stream is created by `Builder::build_message_stream`, before
//! zbus's socket reader starts: a stream made from the finished connection
//! would miss a call that the consumer pipelines right after the handshake
//! (design §8). zbus queues at most [`MAX_QUEUED_INBOUND`] messages.

use super::dispatch::{self, Action};
use super::flow::{self, Link};
use super::inbound::LimitedRead;
use super::{Event, EventSink, ReplyTo, SessionId};
use futures_lite::StreamExt as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use zbus::connection::socket::{BoxedSplit, ReadHalf, Split, WriteHalf};
use zbus::{AuthMechanism, Guid, MessageStream};

/// zbus's inbound queue per connection.
pub const MAX_QUEUED_INBOUND: usize = 16;
/// Longest the handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The server side of the p2p handshake (EXTERNAL, fd passing) over
/// `stream`, with the inbound limits; the message stream starts before the
/// first message can arrive.
///
/// # Errors
/// The handshake failed or took longer than [`HANDSHAKE_TIMEOUT`].
pub async fn handshake(stream: UnixStream) -> zbus::Result<MessageStream> {
    let (read, write) = stream.into_split();
    let read: Box<dyn ReadHalf> = Box::new(LimitedRead::new(Box::new(read)));
    let write: Box<dyn WriteHalf> = Box::new(write);
    let split: BoxedSplit = Split::new(read, write);
    let build = zbus::connection::Builder::socket(split)
        .server(Guid::generate())?
        .p2p()
        .auth_mechanism(AuthMechanism::External)
        .max_queued(MAX_QUEUED_INBOUND)
        .build_message_stream();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, build)
        .await
        .map_err(|_elapsed| zbus::Error::Handshake("timed out".to_owned()))?
}

/// Runs a session on a peer-checked connection until it ends. `shutdown` is
/// a duplicate of the socket, used to close it from any thread.
pub async fn run(stream: UnixStream, shutdown: StdUnixStream, sid: SessionId, sink: EventSink) {
    let Ok(mut messages) = handshake(stream).await else {
        return;
    };
    let conn = zbus::Connection::from(&messages);
    let link = Arc::new(Link::new(shutdown));
    let (outbox, rx) = flow::outbox(sid, Arc::clone(&link), flow::SESSION_FLOW_LIMIT);
    let writer = tokio::spawn(flow::run_writer(conn, rx, Arc::clone(&link), Arc::clone(outbox.flow())));
    sink.deliver(Event::Accepted { sid, outbox: outbox.clone() });
    let mut state = dispatch::State::default();
    loop {
        link.wait_for_room().await;
        let Some(Ok(msg)) = messages.next().await else { break };
        match dispatch::classify(&msg, &mut state) {
            Action::Ignore => {}
            Action::Reply(reply) => {
                outbox.send_message(reply, 0);
            }
            Action::Forward(method, call) => match ReplyTo::new(&msg, method, outbox.clone()) {
                Ok(reply) => sink.deliver(Event::Call { sid, reply, call }),
                Err(_) => break,
            },
        }
    }
    link.close();
    drop(messages);
    // The writer ends once the link is closed; its result is nothing.
    drop(writer.await);
    sink.deliver(Event::Closed { sid });
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
