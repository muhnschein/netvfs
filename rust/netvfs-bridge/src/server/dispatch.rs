// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a session does with an incoming message. No zbus `ObjectServer`: zbus answers nothing itself, so everything is answered here or by the core.
//!
//! Checks in order:
//! 1. Messages other than method calls are ignored.
//! 2. `org.freedesktop.DBus.Peer` on any path: `Ping`, `GetMachineId`; any other member `UnknownMethod`.
//! 3. Another path than `/org/netvfs/Bridge`: `UnknownMethod` "No such object".
//! 4. `Introspect` (interface `org.freedesktop.DBus.Introspectable` or none): the introspection XML, byte for byte.
//! 5. Another interface than `org.netvfs.Bridge1` (or none): `UnknownMethod`.
//! 6. [`args::decode`]: method, signature, arguments.
//! 7. Before a valid `Hello`, any other method fails with `org.netvfs.Error.ProtocolError`.
//!
//! Replies are not sent to a call flagged `NO_REPLY_EXPECTED`.

use super::args::{self, Call};
use super::encode;
use crate::status::Status;
use netvfs_bridge_proto::methods::{INTERFACE, INTROSPECTION_XML, OBJECT_PATH};
use netvfs_bridge_proto::{ErrorName, MethodInfo};
use std::path::Path;
use zbus::Message;
use zbus::message::{Header, Type};
use zbus::names::InterfaceName;
use zbus::zvariant::ObjectPath;

const PEER: &str = "org.freedesktop.DBus.Peer";
const INTROSPECTABLE: &str = "org.freedesktop.DBus.Introspectable";
const MACHINE_ID_FILES: [&str; 2] = ["/var/lib/dbus/machine-id", "/etc/machine-id"];

/// What to do with one incoming message.
#[derive(Debug)]
pub enum Action {
    /// Nothing (not a method call, or no reply wanted).
    Ignore,
    /// Send this reply.
    Reply(Message),
    /// Hand the call to the core.
    Forward(&'static MethodInfo, Call),
}

/// The per-session state the dispatch needs.
#[derive(Debug, Default)]
pub struct State {
    hello: bool,
}

impl State {
    /// Whether a valid `Hello` came.
    #[must_use]
    pub const fn hello_done(&self) -> bool {
        self.hello
    }
}

/// Classifies `msg` and answers what the server answers itself.
#[must_use]
pub fn classify(msg: &Message, state: &mut State) -> Action {
    if msg.message_type() != Type::MethodCall {
        return Action::Ignore;
    }
    let header = msg.header();
    let reply = |result: zbus::Result<Message>| {
        if super::no_reply_expected(msg) {
            Action::Ignore
        } else {
            result.map_or(Action::Ignore, Action::Reply)
        }
    };
    let interface = header.interface().map(InterfaceName::as_str);
    let member = header.member().map_or("", |m| m.as_str());
    if interface == Some(PEER) {
        return reply(peer(&header, member));
    }
    if header.path().map(ObjectPath::as_str) != Some(OBJECT_PATH) {
        return reply(unknown_method(&header, "No such object"));
    }
    if member == "Introspect" && interface.is_none_or(|i| i == INTROSPECTABLE) {
        return reply(Message::method_return(&header).and_then(|r| r.build(&(INTROSPECTION_XML,))));
    }
    if interface.is_some_and(|i| i != INTERFACE) {
        return reply(unknown_method(&header, "No such interface"));
    }
    match args::decode(msg) {
        Err(status) => reply(encode::error_reply(&header, encode::error_name(&status, true), &status)),
        Ok(call) if !state.hello && !matches!(call, Call::Hello { .. }) => {
            let status = Status::new(ErrorName::ProtocolError, "Hello must be the first call");
            reply(encode::error_reply(&header, encode::error_name(&status, false), &status))
        }
        Ok(call) => {
            state.hello = true;
            Action::Forward(call.method(), call)
        }
    }
}

fn unknown_method(header: &Header<'_>, message: &str) -> zbus::Result<Message> {
    let status = Status::new(ErrorName::Unsupported, message);
    encode::error_reply(header, encode::error_name(&status, true), &status)
}

fn peer(header: &Header<'_>, member: &str) -> zbus::Result<Message> {
    match member {
        "Ping" => Message::method_return(header)?.build(&()),
        "GetMachineId" => match machine_id(&MACHINE_ID_FILES.map(Path::new)) {
            Some(id) => Message::method_return(header)?.build(&(id,)),
            None => Message::error(header, "org.freedesktop.DBus.Error.FileNotFound")?
                .build(&("Unable to load the machine id",)),
        },
        _ => Message::error(header, netvfs_bridge_proto::errors::UNKNOWN_METHOD)?
            .build(&("Unknown method invoked on org.freedesktop.DBus.Peer interface",)),
    }
}

fn machine_id(files: &[&Path]) -> Option<String> {
    files.iter().find_map(|path| {
        let text = std::fs::read_to_string(path).ok()?;
        let id = text.trim();
        (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_owned())
    })
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
