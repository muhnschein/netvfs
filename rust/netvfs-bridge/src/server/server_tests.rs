// SPDX-License-Identifier: LGPL-2.1-or-later
// Restriction lints that only add noise to tests.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::flow::{Link, Outgoing};
use super::{
    Arc, ErrorName, Event, EventSink, Message, OBJECT_PATH, Outbox, Reply, ReplyTo, SessionId, Status, flow,
    no_reply_expected,
};
use netvfs_bridge_proto::errors::{INVALID_ARGS, UNKNOWN_METHOD};
use netvfs_bridge_proto::methods::{INTERFACE, find_method};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::os::unix::net::UnixStream;
use tokio::sync::mpsc;
use zbus::message::{Flags, Type};
use zbus::zvariant::OwnedValue;

const SID: SessionId = SessionId(9);

struct Slot {
    outbox: Outbox,
    rx: mpsc::UnboundedReceiver<Outgoing>,
    _peer: UnixStream,
}

fn slot() -> Slot {
    let (ours, peer) = UnixStream::pair().unwrap();
    let (outbox, rx) = flow::outbox(SID, Arc::new(Link::new(ours)), 1000);
    Slot { outbox, rx, _peer: peer }
}

fn call(member: &str, serial: u32, no_reply: bool) -> Message {
    let mut builder = Message::method_call(OBJECT_PATH, member)
        .unwrap()
        .interface(INTERFACE)
        .unwrap()
        .serial(NonZeroU32::new(serial).unwrap())
        .sender(":1.5")
        .unwrap();
    if no_reply {
        builder = builder.with_flags(Flags::NoReplyExpected).unwrap();
    }
    builder.build(&("secret",)).unwrap()
}

fn reply_to(slot: &Slot, member: &str, serial: u32, no_reply: bool) -> ReplyTo {
    ReplyTo::new(&call(member, serial, no_reply), find_method(member).unwrap(), slot.outbox.clone()).unwrap()
}

fn sent(slot: &mut Slot) -> Message {
    let out = slot.rx.try_recv().unwrap();
    assert_eq!(out.flow_bytes, 0);
    out.message
}

fn error_of(message: &Message) -> (String, String) {
    assert_eq!(message.message_type(), Type::Error);
    let (text, _): (String, HashMap<String, OwnedValue>) = message
        .body()
        .deserialize()
        .unwrap_or_else(|_| (message.body().deserialize::<(String,)>().unwrap().0, HashMap::new()));
    (message.header().error_name().unwrap().to_string(), text)
}

#[test]
fn ok_replies_to_the_call() {
    let mut slot = slot();
    let reply = reply_to(&slot, "GetConsent", 41, false);
    assert_eq!(reply.method().name, "GetConsent");
    assert_eq!(reply.session(), SID);
    let debug = format!("{reply:?}");
    assert!(debug.contains("GetConsent") && debug.contains("41") && !debug.contains("secret"), "{debug}");
    reply.ok(&Reply::Text("granted".to_owned()));
    let message = sent(&mut slot);
    assert_eq!(message.message_type(), Type::MethodReturn);
    assert_eq!(message.header().reply_serial(), NonZeroU32::new(41));
    assert_eq!(message.header().destination().unwrap().as_str(), ":1.5");
    assert_eq!(message.body().deserialize::<(String,)>().unwrap().0, "granted");
    assert!(slot.rx.try_recv().is_err());

    let plain = Message::method_call(OBJECT_PATH, "Close").unwrap().build(&(1u32,)).unwrap();
    let reply = ReplyTo::new(&plain, find_method("Close").unwrap(), slot.outbox.clone()).unwrap();
    reply.ok(&Reply::Empty);
    let message = sent(&mut slot);
    assert!(message.header().destination().is_none());
    assert_eq!(message.header().reply_serial(), Some(plain.primary_header().serial_num()));
}

#[test]
fn a_reply_of_the_wrong_signature_is_internal() {
    let mut slot = slot();
    reply_to(&slot, "GetConsent", 2, false).ok(&Reply::Id(3));
    assert_eq!(
        error_of(&sent(&mut slot)),
        ("org.netvfs.Error.Internal".to_owned(), "Cannot encode the reply".to_owned())
    );
    assert!(slot.rx.try_recv().is_err());
}

#[test]
fn fail_and_refuse() {
    let mut slot = slot();
    let cases = [
        (Status::invalid_args("bad"), false, "org.netvfs.Error.ProtocolError"),
        (Status::invalid_args("bad"), true, INVALID_ARGS),
        (Status::new(ErrorName::Unsupported, "bad"), false, "org.netvfs.Error.Unsupported"),
        (Status::new(ErrorName::Unsupported, "bad"), true, UNKNOWN_METHOD),
        (Status::new(ErrorName::NotFound, "bad"), true, "org.netvfs.Error.NotFound"),
        (Status::permission_denied("bad"), false, "org.netvfs.Error.PermissionDenied"),
    ];
    for (n, (status, validation, name)) in cases.into_iter().enumerate() {
        let serial = u32::try_from(n).unwrap() + 1;
        let reply = reply_to(&slot, "Stat", serial, false);
        if validation {
            reply.refuse(&status);
        } else {
            reply.fail(&status);
        }
        let message = sent(&mut slot);
        assert_eq!(error_of(&message), (name.to_owned(), "bad".to_owned()));
        assert_eq!(message.header().reply_serial(), NonZeroU32::new(serial));
        assert!(slot.rx.try_recv().is_err(), "one answer only");
    }
}

#[test]
fn dropped_unanswered_is_internal() {
    let mut slot = slot();
    drop(reply_to(&slot, "Stat", 5, false));
    let message = sent(&mut slot);
    assert_eq!(
        error_of(&message),
        ("org.netvfs.Error.Internal".to_owned(), "The request was dropped".to_owned())
    );
    assert_eq!(message.header().reply_serial(), NonZeroU32::new(5));
    assert!(slot.rx.try_recv().is_err());
}

#[test]
fn no_reply_expected_sends_nothing() {
    let mut slot = slot();
    reply_to(&slot, "GetConsent", 1, true).ok(&Reply::Text("x".to_owned()));
    reply_to(&slot, "GetConsent", 2, true).ok(&Reply::Empty);
    reply_to(&slot, "Stat", 3, true).fail(&Status::invalid_args("x"));
    reply_to(&slot, "Stat", 4, true).refuse(&Status::invalid_args("x"));
    drop(reply_to(&slot, "Stat", 5, true));
    assert!(slot.rx.try_recv().is_err());
    assert!(no_reply_expected(&call("Stat", 6, true)));
    assert!(!no_reply_expected(&call("Stat", 6, false)));
}

#[test]
fn a_closed_session_drops_replies() {
    let mut slot = slot();
    let reply = reply_to(&slot, "GetConsent", 1, false);
    slot.outbox.close();
    reply.ok(&Reply::Text("x".to_owned()));
    drop(reply_to(&slot, "Stat", 2, false));
    assert!(slot.rx.try_recv().is_err());
}

#[test]
fn event_sink_and_ids() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sink = EventSink::channel(tx);
    assert_eq!(format!("{sink:?}"), "EventSink");
    sink.deliver(Event::Closed { sid: SID });
    assert!(matches!(rx.try_recv().unwrap(), Event::Closed { sid: SID }));
    drop(rx);
    sink.deliver(Event::Closed { sid: SID });

    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let sink = EventSink::new(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    sink.deliver(Event::Refused { reason: Status::permission_denied("x") });
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);

    assert_eq!(SessionId(12).to_string(), "12");
    assert!(SessionId(1) < SessionId(2));
}
