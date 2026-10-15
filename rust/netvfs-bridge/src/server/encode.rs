// SPDX-License-Identifier: LGPL-2.1-or-later
//! Replies, error replies and signals of `org.netvfs.Bridge1` (XB-8, XB-9,
//! XC-24): the port of the C++ bridge's `protocol.cpp` (netvfs 0.4).
//!
//! Every string the bridge sends goes through [`wire_text`]: D-Bus strings
//! must be valid UTF-8 without NUL, so NUL becomes U+FFFD (as the C++
//! `WireWriter` did; a peer such as libdbus drops the connection on an
//! invalid string).

use crate::status::Status;
use netvfs_bridge_proto::errors::{INVALID_ARGS, UNKNOWN_METHOD};
use netvfs_bridge_proto::methods::{INTERFACE, OBJECT_PATH};
use netvfs_bridge_proto::{ErrorName, WireCapabilities, WireEntry, WireLocation, WireNearby, WireWalkItem};
use std::collections::HashMap;
use zbus::Message;
use zbus::message::Header;
use zbus::zvariant::{OwnedValue, Value};

/// The bridge version `Hello` announces.
pub const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A string as the wire can carry it: NUL becomes U+FFFD.
#[must_use]
pub fn wire_text(s: &str) -> String {
    s.replace('\0', "\u{fffd}")
}

/// Bytes as a wire string (owner, group, content type of entries from the
/// backends): lossy UTF-8, NUL as U+FFFD.
#[must_use]
pub fn wire_text_from_bytes(bytes: &[u8]) -> String {
    wire_text(&String::from_utf8_lossy(bytes))
}

/// An entry with its strings made wire-safe.
#[must_use]
pub fn wire_entry(entry: &WireEntry) -> WireEntry {
    WireEntry {
        owner: wire_text(&entry.owner),
        group: wire_text(&entry.group),
        content_type: wire_text(&entry.content_type),
        ..entry.clone()
    }
}

fn wire_texts(items: &[String]) -> Vec<String> {
    items.iter().map(|s| wire_text(s)).collect()
}

/// The return values of a successful call, one variant per output
/// signature of the method table.
#[derive(Debug)]
pub enum Reply {
    /// `""`: no return values.
    Empty,
    /// `Hello`: `s` (the bridge version).
    Hello,
    /// `s`: `GetConsent`, `ConnectAdHoc`.
    Text(String),
    /// `a(sssa{sv})`: `ListLocations`.
    Locations(Vec<WireLocation>),
    /// `(asasx)`: `Capabilities`.
    Capabilities(WireCapabilities),
    /// `u`: `List` (request id), `Upload`, `Download`, `CopyAcross`,
    /// `RemoveTree`, `Walk` (job id).
    Id(u32),
    /// `(ayyyxxxxixxssqays)`: `Stat`.
    Entry(WireEntry),
    /// `ay`: `ReadLink`, `Checksum`, `Read`.
    Bytes(Vec<u8>),
    /// `xxx`: `SpaceInfo` (free, total, used; -1 unknown).
    Space {
        /// Free bytes.
        free: i64,
        /// Total bytes.
        total: i64,
        /// Used bytes.
        used: i64,
    },
    /// `ux`: `OpenRead` (handle, size).
    Opened {
        /// The handle.
        handle: u32,
        /// The file size, -1 if not known.
        size: i64,
    },
}

impl Reply {
    /// The D-Bus signature of the return values.
    #[must_use]
    pub const fn signature(&self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Hello | Self::Text(_) => "s",
            Self::Locations(_) => "a(sssa{sv})",
            Self::Capabilities(_) => "(asasx)",
            Self::Id(_) => "u",
            Self::Entry(_) => netvfs_bridge_proto::methods::ENTRY_SIGNATURE,
            Self::Bytes(_) => "ay",
            Self::Space { .. } => "xxx",
            Self::Opened { .. } => "ux",
        }
    }

    /// The method return for the call with `call`'s header.
    ///
    /// # Errors
    /// zbus cannot build the message (a value the wire cannot carry).
    pub fn build(&self, call: &Header<'_>) -> zbus::Result<Message> {
        let reply = Message::method_return(call)?;
        match self {
            Self::Empty => reply.build(&()),
            Self::Hello => reply.build(&(BRIDGE_VERSION,)),
            Self::Text(s) => reply.build(&(wire_text(s),)),
            Self::Locations(list) => reply.build(&(list.iter().map(wire_location).collect::<Vec<_>>(),)),
            Self::Capabilities(c) => reply.build(&(WireCapabilities {
                flags: wire_texts(&c.flags),
                checksum_algorithms: wire_texts(&c.checksum_algorithms),
                max_name_bytes: c.max_name_bytes,
            },)),
            Self::Id(id) => reply.build(&(*id,)),
            Self::Entry(e) => reply.build(&(wire_entry(e),)),
            Self::Bytes(b) => reply.build(&(b,)),
            Self::Space { free, total, used } => reply.build(&(*free, *total, *used)),
            Self::Opened { handle, size } => reply.build(&(*handle, *size)),
        }
    }
}

fn wire_location(l: &WireLocation) -> (String, String, String, &HashMap<String, OwnedValue>) {
    (wire_text(&l.id), wire_text(&l.provider), wire_text(&l.name), &l.info)
}

/// The D-Bus error name for a failure. `from_validation`: the failure comes
/// from argument validation, where `ProtocolError` is
/// `org.freedesktop.DBus.Error.InvalidArgs` and `Unsupported` is
/// `org.freedesktop.DBus.Error.UnknownMethod` (`Protocol::errorNameFor`).
#[must_use]
pub fn error_name(status: &Status, from_validation: bool) -> &'static str {
    match (status.name, from_validation) {
        (ErrorName::ProtocolError, true) => INVALID_ARGS,
        (ErrorName::Unsupported, true) => UNKNOWN_METHOD,
        (name, _) => name.dbus_name(),
    }
}

/// The error reply `name` to the call with `call`'s header: the message as
/// first argument (the bare name when the message is empty), then an
/// `a{sv}` with `detail` and `retryAfterMs` when the status has them.
///
/// # Errors
/// zbus cannot build the message (an invalid error name).
pub fn error_reply(call: &Header<'_>, name: &str, status: &Status) -> zbus::Result<Message> {
    let reply = Message::error(call, name)?;
    let short = name.rsplit('.').next().unwrap_or(name);
    let text = if status.message.is_empty() { short.to_owned() } else { wire_text(&status.message) };
    let extra = status_extra(status);
    if extra.is_empty() { reply.build(&(text,)) } else { reply.build(&(text, extra)) }
}

/// `detail` and `retryAfterMs` of a status, as error replies and
/// `JobFinished` carry them (XC-24).
#[must_use]
pub fn status_extra(status: &Status) -> HashMap<String, Value<'static>> {
    let mut extra = HashMap::new();
    if !status.detail.is_empty() {
        extra.insert("detail".to_owned(), Value::from(wire_text(&status.detail)));
    }
    if status.retry_after_ms >= 0 {
        extra.insert("retryAfterMs".to_owned(), Value::from(status.retry_after_ms));
    }
    extra
}

/// `(name, message)` of `ListDone` / `JobFinished`: empty on success.
fn outcome(result: &Result<(), Status>) -> (&'static str, String) {
    match result {
        Ok(()) => ("", String::new()),
        Err(s) => (s.name.as_str(), wire_text(&s.message)),
    }
}

/// A signal of `org.netvfs.Bridge1`, as the bridge sends it.
#[derive(Debug, Clone, PartialEq)]
pub enum OutSignal {
    /// `s`: `granted`, `denied` or `unknown`.
    ConsentChanged(String),
    /// `""`.
    LocationsChanged,
    /// `a(sssq)`.
    NearbyChanged(Vec<WireNearby>),
    /// `ua(ayyyxxxxixxssqays)`.
    ListBatch {
        /// The `List` request id.
        request: u32,
        /// The entries.
        entries: Vec<WireEntry>,
    },
    /// `uss`.
    ListDone {
        /// The `List` request id.
        request: u32,
        /// The outcome.
        result: Result<(), Status>,
    },
    /// `uxx`.
    JobProgress {
        /// The job id.
        job: u32,
        /// Bytes done.
        done: i64,
        /// Bytes in all, -1 if not known.
        total: i64,
    },
    /// `ua(ay(ayyyxxxxixxssqays))`.
    WalkBatch {
        /// The job id.
        job: u32,
        /// Entries with their paths.
        items: Vec<WireWalkItem>,
    },
    /// `ussa{sv}`; the status's `detail` and `retryAfterMs` are added to
    /// `extra`.
    JobFinished {
        /// The job id.
        job: u32,
        /// The outcome.
        result: Result<(), Status>,
        /// Job results (`files`, `dirs`, …).
        extra: HashMap<String, OwnedValue>,
    },
    /// `ssa{sv}`.
    Question {
        /// The question id.
        id: String,
        /// `identity-unknown`, `keyboard-interactive`, `insecure-consent`, …
        kind: String,
        /// What to show.
        details: HashMap<String, OwnedValue>,
    },
}

impl OutSignal {
    /// The member name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ConsentChanged(_) => "ConsentChanged",
            Self::LocationsChanged => "LocationsChanged",
            Self::NearbyChanged(_) => "NearbyChanged",
            Self::ListBatch { .. } => "ListBatch",
            Self::ListDone { .. } => "ListDone",
            Self::JobProgress { .. } => "JobProgress",
            Self::WalkBatch { .. } => "WalkBatch",
            Self::JobFinished { .. } => "JobFinished",
            Self::Question { .. } => "Question",
        }
    }

    /// The signal message.
    ///
    /// # Errors
    /// zbus cannot build the message (a value the wire cannot carry).
    pub fn build(&self) -> zbus::Result<Message> {
        let signal = Message::signal(OBJECT_PATH, INTERFACE, self.name())?;
        match self {
            Self::ConsentChanged(s) => signal.build(&(wire_text(s),)),
            Self::LocationsChanged => signal.build(&()),
            Self::NearbyChanged(items) => signal.build(&(items.iter().map(wire_nearby).collect::<Vec<_>>(),)),
            Self::ListBatch { request, entries } => {
                signal.build(&(*request, entries.iter().map(wire_entry).collect::<Vec<_>>()))
            }
            Self::ListDone { request, result } => {
                let (name, message) = outcome(result);
                signal.build(&(*request, name, message))
            }
            Self::JobProgress { job, done, total } => signal.build(&(*job, *done, *total)),
            Self::WalkBatch { job, items } => {
                signal.build(&(*job, items.iter().map(wire_walk_item).collect::<Vec<_>>()))
            }
            Self::JobFinished { job, result, extra } => {
                let (name, message) = outcome(result);
                let added = result.as_ref().err().map(status_extra).unwrap_or_default();
                signal.build(&(*job, name, message, job_extra(extra, &added)))
            }
            Self::Question { id, kind, details } => signal.build(&(wire_text(id), wire_text(kind), details)),
        }
    }
}

fn wire_nearby(n: &WireNearby) -> WireNearby {
    WireNearby {
        name: wire_text(&n.name),
        provider: wire_text(&n.provider),
        host: wire_text(&n.host),
        port: n.port,
    }
}

fn wire_walk_item(item: &WireWalkItem) -> WireWalkItem {
    WireWalkItem { path: item.path.clone(), entry: wire_entry(&item.entry) }
}

/// The `a{sv}` of `JobFinished`: the job's results, plus the status's
/// `detail` and `retryAfterMs` (which win over results of the same name).
fn job_extra<'a>(
    extra: &'a HashMap<String, OwnedValue>,
    added: &'a HashMap<String, Value<'static>>,
) -> HashMap<&'a str, &'a Value<'static>> {
    extra.iter().map(|(k, v)| (k.as_str(), &**v)).chain(added.iter().map(|(k, v)| (k.as_str(), v))).collect()
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
