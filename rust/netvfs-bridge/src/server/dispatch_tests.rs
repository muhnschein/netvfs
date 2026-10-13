// SPDX-License-Identifier: LGPL-2.1-or-later
// tst_bridgeserver: the server's own answers, in the C++ order of checks.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::*;
use crate::test_support::{TempDir, write_file};
use netvfs_bridge_proto::errors::{INVALID_ARGS, UNKNOWN_METHOD};
use zbus::export::serde::Serialize;
use zbus::message::{Builder, Flags};
use zbus::zvariant::DynamicType;

fn call(path: &str, interface: Option<&str>, member: &str) -> Builder<'static> {
    let mut builder = Message::method_call(path.to_owned(), member.to_owned()).unwrap();
    if let Some(interface) = interface {
        builder = builder.interface(interface.to_owned()).unwrap();
    }
    builder
}

fn bridge<B: Serialize + DynamicType>(member: &str, body: &B) -> Message {
    call(OBJECT_PATH, Some(INTERFACE), member).build(body).unwrap()
}

fn hello() -> Message {
    bridge("Hello", &(1u32, "test"))
}

fn reply(msg: &Message, state: &mut State) -> Message {
    match classify(msg, state) {
        Action::Reply(reply) => reply,
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// The error name and message of an error reply.
fn error(msg: &Message, state: &mut State) -> (String, String) {
    let reply = reply(msg, state);
    assert_eq!(reply.message_type(), Type::Error);
    assert_eq!(reply.header().reply_serial(), Some(msg.primary_header().serial_num()));
    let name = reply.header().error_name().unwrap().to_string();
    let text = reply.body().deserialize::<(String,)>().map_or_else(
        |_| {
            reply
                .body()
                .deserialize::<(String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>)>()
                .unwrap()
                .0
        },
        |(text,)| text,
    );
    (name, text)
}

fn fresh() -> State {
    State::default()
}

#[test]
fn peer_interface_on_any_path() {
    for path in ["/", OBJECT_PATH, "/elsewhere"] {
        let ping = call(path, Some(PEER), "Ping").build(&()).unwrap();
        let answer = reply(&ping, &mut fresh());
        assert_eq!(answer.message_type(), Type::MethodReturn);
        assert_eq!(answer.header().reply_serial(), Some(ping.primary_header().serial_num()));
        assert!(answer.body().is_empty());
    }
    let other = call("/", Some(PEER), "Pong").build(&()).unwrap();
    assert_eq!(
        error(&other, &mut fresh()),
        (
            UNKNOWN_METHOD.to_owned(),
            "Unknown method invoked on org.freedesktop.DBus.Peer interface".to_owned()
        )
    );
    // The machine id is answered whether or not the host has one.
    let get = call("/", Some(PEER), "GetMachineId").build(&()).unwrap();
    let answer = reply(&get, &mut fresh());
    match answer.message_type() {
        Type::MethodReturn => {
            let (id,): (String,) = answer.body().deserialize().unwrap();
            assert_eq!(id.len(), 32);
        }
        _ => assert_eq!(
            answer.header().error_name().unwrap().as_str(),
            "org.freedesktop.DBus.Error.FileNotFound"
        ),
    }
}

#[test]
fn machine_id_files() {
    let dir = TempDir::new();
    let missing = dir.path().join("missing");
    let bad = dir.path().join("bad");
    let short = dir.path().join("short");
    let good = dir.path().join("good");
    write_file(&bad, b"0123456789abcdef0123456789abcdeg\n");
    write_file(&short, b"0123456789abcdef\n");
    write_file(&good, b"0123456789ABCDEF0123456789abcdef\n");
    let id = machine_id(&[&missing, &bad, &short, &good]);
    assert_eq!(id.as_deref(), Some("0123456789ABCDEF0123456789abcdef"));
    assert_eq!(machine_id(&[&missing, &bad]), None);
    assert_eq!(machine_id(&[]), None);
}

#[test]
fn introspection_is_verbatim() {
    for interface in [None, Some(INTROSPECTABLE)] {
        let msg = call(OBJECT_PATH, interface, "Introspect").build(&()).unwrap();
        let answer = reply(&msg, &mut fresh());
        assert_eq!(answer.message_type(), Type::MethodReturn);
        let (xml,): (String,) = answer.body().deserialize().unwrap();
        assert_eq!(xml, INTROSPECTION_XML);
    }
    // Not on another path, nor on the bridge interface.
    let elsewhere = call("/", Some(INTROSPECTABLE), "Introspect").build(&()).unwrap();
    assert_eq!(error(&elsewhere, &mut fresh()), (UNKNOWN_METHOD.to_owned(), "No such object".to_owned()));
    let bridge_member = call(OBJECT_PATH, Some(INTERFACE), "Introspect").build(&()).unwrap();
    assert_eq!(error(&bridge_member, &mut fresh()), (UNKNOWN_METHOD.to_owned(), "No such method".to_owned()));
}

#[test]
fn unknown_object_interface_member() {
    let mut state = fresh();
    let path = call("/org/netvfs", Some(INTERFACE), "Hello").build(&(1u32, "x")).unwrap();
    assert_eq!(error(&path, &mut state), (UNKNOWN_METHOD.to_owned(), "No such object".to_owned()));
    let interface = call(OBJECT_PATH, Some("org.netvfs.Bridge2"), "Hello").build(&(1u32, "x")).unwrap();
    assert_eq!(error(&interface, &mut state), (UNKNOWN_METHOD.to_owned(), "No such interface".to_owned()));
    let member = bridge("Frobnicate", &());
    assert_eq!(error(&member, &mut state), (UNKNOWN_METHOD.to_owned(), "No such method".to_owned()));
    assert!(!state.hello_done());
}

#[test]
fn arguments_are_checked_before_hello() {
    let mut state = fresh();
    let wrong = bridge("Hello", &("x",));
    assert_eq!(error(&wrong, &mut state), (INVALID_ARGS.to_owned(), "Hello takes (us)".to_owned()));
    let zero = bridge("Hello", &(0u32, "x"));
    assert_eq!(error(&zero, &mut state).0, INVALID_ARGS);
    let bad_path = bridge("Stat", &("account:1", b"/a/../b".as_slice(), true, ""));
    assert_eq!(error(&bad_path, &mut state).0, "org.netvfs.Error.InvalidName");
    assert!(!state.hello_done());
}

#[test]
fn hello_must_come_first() {
    let mut state = fresh();
    let early = bridge("GetConsent", &());
    assert_eq!(
        error(&early, &mut state),
        ("org.netvfs.Error.ProtocolError".to_owned(), "Hello must be the first call".to_owned())
    );
    // Without an interface the bridge interface is meant.
    let first = call(OBJECT_PATH, None, "Hello").build(&(1u32, "x")).unwrap();
    match classify(&first, &mut state) {
        Action::Forward(method, Call::Hello { protocol: 1, client }) => {
            assert_eq!(method.name, "Hello");
            assert_eq!(client, "x");
        }
        other => panic!("expected Hello, got {other:?}"),
    }
    assert!(state.hello_done());
    match classify(&early, &mut state) {
        Action::Forward(method, Call::GetConsent) => assert_eq!(method.name, "GetConsent"),
        other => panic!("expected GetConsent, got {other:?}"),
    }
    // A second Hello is the core's to answer.
    assert!(matches!(classify(&hello(), &mut state), Action::Forward(_, Call::Hello { .. })));
}

#[test]
fn no_reply_expected_and_other_types() {
    let mut state = fresh();
    let quiet =
        |builder: Builder<'static>| builder.with_flags(Flags::NoReplyExpected).unwrap().build(&()).unwrap();
    assert!(matches!(classify(&quiet(call("/", Some(PEER), "Ping")), &mut state), Action::Ignore));
    assert!(matches!(classify(&quiet(call("/x", Some(INTERFACE), "Hello")), &mut state), Action::Ignore));
    assert!(matches!(classify(&quiet(call(OBJECT_PATH, None, "Introspect")), &mut state), Action::Ignore));
    assert!(matches!(
        classify(&quiet(call(OBJECT_PATH, Some(INTERFACE), "GetConsent")), &mut state),
        Action::Ignore
    ));
    // A valid call is forwarded anyway; the reply slot drops the answer.
    let quiet_hello = call(OBJECT_PATH, Some(INTERFACE), "Hello")
        .with_flags(Flags::NoReplyExpected)
        .unwrap()
        .build(&(1u32, "x"))
        .unwrap();
    assert!(matches!(classify(&quiet_hello, &mut state), Action::Forward(..)));

    let signal = Message::signal(OBJECT_PATH, INTERFACE, "Hello").unwrap().build(&(1u32, "x")).unwrap();
    assert!(matches!(classify(&signal, &mut fresh()), Action::Ignore));
    let ping = call("/", Some(PEER), "Ping").build(&()).unwrap();
    let ret = Message::method_return(&ping.header()).unwrap().build(&()).unwrap();
    assert!(matches!(classify(&ret, &mut fresh()), Action::Ignore));
    let err = Message::error(&ping.header(), UNKNOWN_METHOD).unwrap().build(&("x",)).unwrap();
    assert!(matches!(classify(&err, &mut fresh()), Action::Ignore));
}
