// SPDX-License-Identifier: LGPL-2.1-or-later
//! Socket front: listening, peer check, one session per consumer connection, raw D-Bus dispatch, outgoing FIFO with flow control.
//!
//! Knows nothing of consent, locations or jobs. Hands each valid call up as an [`Event`] through an [`EventSink`]; replies and signals come back through [`ReplyTo`] and [`Outbox`].
//! Per session: `Accepted`, `Call`s in send order, `Closed`.
//!
//! Done before any event:
//! - peer check on the raw socket before any byte is read; refused peer closed without reply, reported as [`Event::Refused`].
//! - p2p handshake (EXTERNAL, fd passing), at most 30 s.
//! - inbound limits: header declaring more than [`inbound::MAX_MESSAGE_BYTES`] bytes or [`inbound::MAX_MESSAGE_FDS`] descriptors closes the connection; at most 16 messages in zbus's queue.
//! - `org.freedesktop.DBus.Peer` (`Ping`, `GetMachineId`, any path), verbatim introspection XML, `UnknownMethod` for other paths, interfaces and members, `InvalidArgs` for wrong signature or argument, `org.netvfs.Error.InvalidName` for a bad path ([`args`]).
//! - `org.netvfs.Error.ProtocolError` for any method before a valid `Hello`.
//!
//! Core duties for an [`Event::Call`]:
//! - `PermissionDenied` for a call with [`args::Call::needs_consent`] until consent is granted (`ListLocations` answers an empty list instead).
//! - Answer through the [`ReplyTo`] exactly once: [`ReplyTo::ok`] with a [`Reply`] of the output signature, [`ReplyTo::fail`] for a netvfs error, [`ReplyTo::refuse`] for a validation error. A dropped `ReplyTo` replies `org.netvfs.Error.Internal`; replies of a closed session are dropped. Answer `Hello` with [`Reply::Hello`].
//!
//! The core keeps an `Accepted` session's [`Outbox`] to send signals (only to sessions that said `Hello`) and drops it after `Closed`.
//! [`Outbox::close`] closes a session; `Closed` follows. Streamed signals (`ListBatch`, `WalkBatch`) go through [`Outbox::stream`] from worker threads and block on the session's [`FlowBudget`].

pub mod args;
pub mod dispatch;
pub mod encode;
pub mod flow;
pub mod inbound;
pub mod listener;
pub mod paths;
pub mod session;

pub use args::Call;
pub use encode::{OutSignal, Reply};
pub use flow::{FlowBudget, Outbox};
pub use listener::{ListenAddress, Listener};
pub use paths::NPath;

use crate::status::Status;
use netvfs_bridge_proto::methods::OBJECT_PATH;
use netvfs_bridge_proto::{ErrorName, MethodInfo};
use std::fmt;
use std::sync::Arc;
use zbus::Message;

/// A consumer connection, numbered from 1 in the order of acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What the server reports to the core.
#[derive(Debug)]
pub enum Event {
    /// A peer passed the check and the handshake.
    Accepted {
        /// The session.
        sid: SessionId,
        /// Where its replies and signals go.
        outbox: Outbox,
    },
    /// A valid call (after `Hello`), to be answered through `reply`.
    Call {
        /// The session.
        sid: SessionId,
        /// The answer slot.
        reply: ReplyTo,
        /// The validated call.
        call: Call,
    },
    /// The session ended (disconnect, protocol violation, [`Outbox::close`]).
    Closed {
        /// The session.
        sid: SessionId,
    },
    /// Connection refused by the peer check; reason is for the warning log.
    Refused {
        /// Why.
        reason: Status,
    },
}

/// Where the server delivers [`Event`]s.
#[derive(Clone)]
pub struct EventSink(Arc<dyn Fn(Event) + Send + Sync>);

impl EventSink {
    /// A sink calling `deliver` for each event.
    pub fn new(deliver: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Self(Arc::new(deliver))
    }

    /// A sink feeding an unbounded channel (events are dropped once its receiver is gone).
    #[must_use]
    pub fn channel(tx: tokio::sync::mpsc::UnboundedSender<Event>) -> Self {
        Self::new(move |event| {
            // A closed channel means the core has stopped: nothing to do.
            drop(tx.send(event));
        })
    }

    pub(crate) fn deliver(&self, event: Event) {
        (self.0)(event);
    }
}

impl fmt::Debug for EventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventSink")
    }
}

/// The answer slot of one call.
pub struct ReplyTo {
    call: Message,
    method: &'static MethodInfo,
    outbox: Outbox,
    no_reply: bool,
    answered: bool,
}

impl fmt::Debug for ReplyTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyTo")
            .field("method", &self.method.name)
            .field("serial", &self.call.primary_header().serial_num())
            .field("no_reply", &self.no_reply)
            .finish_non_exhaustive()
    }
}

impl ReplyTo {
    pub(crate) fn new(call: &Message, method: &'static MethodInfo, outbox: Outbox) -> zbus::Result<Self> {
        let header = call.header();
        let mut stub =
            Message::method_call(OBJECT_PATH, method.name)?.serial(call.primary_header().serial_num());
        if let Some(sender) = header.sender() {
            stub = stub.sender(sender.to_owned())?;
        }
        Ok(Self {
            call: stub.build(&())?,
            method,
            outbox,
            no_reply: no_reply_expected(call),
            answered: false,
        })
    }

    /// The method that was called.
    #[must_use]
    pub const fn method(&self) -> &'static MethodInfo {
        self.method
    }

    /// The session of the call.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.outbox.session()
    }

    /// Replies with return values.
    pub fn ok(mut self, reply: &Reply) {
        let message = if reply.signature() == self.method.output {
            reply.build(&self.call.header()).ok()
        } else {
            None
        };
        match message {
            Some(message) => self.send(message),
            None => self.fail_with(&Status::new(ErrorName::Internal, "Cannot encode the reply"), false),
        }
    }

    /// Replies with the netvfs error `org.netvfs.Error.<name>`.
    pub fn fail(mut self, status: &Status) {
        self.fail_with(status, false);
    }

    /// Replies with a validation error.
    pub fn refuse(mut self, status: &Status) {
        self.fail_with(status, true);
    }

    fn fail_with(&mut self, status: &Status, from_validation: bool) {
        let name = encode::error_name(status, from_validation);
        if let Ok(message) = encode::error_reply(&self.call.header(), name, status) {
            self.send(message);
        }
        self.answered = true;
    }

    fn send(&mut self, message: Message) {
        self.answered = true;
        if !self.no_reply {
            self.outbox.send_message(message, 0);
        }
    }
}

impl Drop for ReplyTo {
    fn drop(&mut self) {
        if !self.answered {
            self.fail_with(&Status::new(ErrorName::Internal, "The request was dropped"), false);
        }
    }
}

fn no_reply_expected(msg: &Message) -> bool {
    msg.primary_header().flags().contains(zbus::message::Flags::NoReplyExpected)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
