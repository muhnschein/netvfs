// SPDX-License-Identifier: LGPL-2.1-or-later
// Sessions end to end against a stub core (netvfs 0.4's C++
// tst_bridgeserver): the hello race, the server's own answers, errors,
// descriptor passing, the inbound limits and flow control (C-10).
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{Arc, Duration, EventSink, SessionId, StdUnixStream, UnixStream, run};
use crate::server::encode::OutSignal;
use crate::server::{Outbox, inbound};
use crate::test_support::{RawClient, Seen, read_message, resident_bytes, stub_core, wire_entry};
use netvfs_bridge_proto::errors::{INVALID_ARGS, UNKNOWN_METHOD};
use netvfs_bridge_proto::limits::FLOW_LIMIT;
use netvfs_bridge_proto::methods::{INTERFACE, INTROSPECTION_XML, OBJECT_PATH};
use std::os::fd::AsFd as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedReceiver;
use zbus::Message;
use zbus::export::serde::Serialize;
use zbus::message::Type;
use zbus::zvariant::{DynamicType, Fd};

const SID: SessionId = SessionId(1);
const WAIT: Duration = Duration::from_secs(5);

/// A session on one end of a socket pair; the other end.
fn start(sink: EventSink) -> (UnixStream, tokio::task::JoinHandle<()>) {
    let (server, client) = UnixStream::pair().unwrap();
    let shutdown = StdUnixStream::from(server.as_fd().try_clone_to_owned().unwrap());
    (client, tokio::spawn(run(server, shutdown, SID, sink)))
}

async fn zbus_client(stream: UnixStream) -> zbus::Connection {
    zbus::connection::Builder::unix_stream(stream).p2p().build().await.unwrap()
}

async fn next(seen: &mut UnboundedReceiver<Seen>) -> Seen {
    tokio::time::timeout(WAIT, seen.recv()).await.unwrap().unwrap()
}

async fn accepted(seen: &mut UnboundedReceiver<Seen>) -> Outbox {
    match next(seen).await {
        Seen::Accepted(sid, outbox) => {
            assert_eq!(sid, SID);
            outbox
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
}

async fn closed(seen: &mut UnboundedReceiver<Seen>) {
    loop {
        if let Seen::Closed(sid) = next(seen).await {
            assert_eq!(sid, SID);
            return;
        }
    }
}

fn bridge_call<B: Serialize + DynamicType>(member: &str, body: &B) -> Message {
    Message::method_call(OBJECT_PATH, member).unwrap().interface(INTERFACE).unwrap().build(body).unwrap()
}

fn hello() -> Message {
    bridge_call("Hello", &(1u32, "test"))
}

async fn call<B: Serialize + DynamicType>(
    client: &zbus::Connection,
    path: &str,
    interface: &str,
    member: &str,
    body: &B,
) -> zbus::Result<Message> {
    tokio::time::timeout(WAIT, client.call_method(None::<&str>, path, Some(interface), member, body))
        .await
        .unwrap()
}

fn method_error(result: zbus::Result<Message>) -> (String, String) {
    match result {
        Err(zbus::Error::MethodError(name, text, _)) => (name.to_string(), text.unwrap_or_default()),
        other => panic!("expected an error reply, got {other:?}"),
    }
}

/// XB-3: a call pipelined right behind `BEGIN` is not lost (design §8:
/// the message stream exists before zbus's reader starts).
#[tokio::test]
async fn hello_right_after_the_handshake_is_answered() {
    for _ in 0..200 {
        let (sink, mut seen) = stub_core();
        let (stream, session) = start(sink);
        let mut client = RawClient::authenticate(stream).await;
        let hello = hello();
        client.begin_with(&[&hello]).await;
        let reply = tokio::time::timeout(WAIT, client.receive()).await.unwrap().unwrap();
        assert_eq!(reply.message_type(), Type::MethodReturn);
        assert_eq!(reply.header().reply_serial(), Some(hello.primary_header().serial_num()));
        let (version, _, _): (u32, String, Vec<String>) = reply.body().deserialize().unwrap();
        assert_eq!(version, 1);
        drop(client);
        tokio::time::timeout(WAIT, session).await.unwrap().unwrap();
        assert!(matches!(next(&mut seen).await, Seen::Accepted(SID, _)));
        assert!(matches!(next(&mut seen).await, Seen::Call(SID, "Hello")));
        assert!(matches!(next(&mut seen).await, Seen::Closed(SID)));
    }
}

#[tokio::test]
async fn own_answers_hello_first_and_consent_free_calls() {
    let (sink, mut seen) = stub_core();
    let (stream, session) = start(sink);
    let client = zbus_client(stream).await;
    let _outbox = accepted(&mut seen).await;

    let xml =
        call(&client, OBJECT_PATH, "org.freedesktop.DBus.Introspectable", "Introspect", &()).await.unwrap();
    assert_eq!(xml.body().deserialize::<(String,)>().unwrap().0, INTROSPECTION_XML);
    let pong = call(&client, "/", "org.freedesktop.DBus.Peer", "Ping", &()).await.unwrap();
    assert_eq!(pong.message_type(), Type::MethodReturn);
    assert_eq!(
        method_error(call(&client, "/x", INTERFACE, "Hello", &(1u32, "t")).await),
        (UNKNOWN_METHOD.to_owned(), "No such object".to_owned())
    );
    assert_eq!(
        method_error(call(&client, OBJECT_PATH, INTERFACE, "Nope", &()).await),
        (UNKNOWN_METHOD.to_owned(), "No such method".to_owned())
    );
    assert_eq!(
        method_error(call(&client, OBJECT_PATH, INTERFACE, "GetConsent", &()).await),
        ("org.netvfs.Error.ProtocolError".to_owned(), "Hello must be the first call".to_owned())
    );
    assert_eq!(method_error(call(&client, OBJECT_PATH, INTERFACE, "Hello", &(1u32,)).await).0, INVALID_ARGS);
    // The core's answers.
    assert_eq!(
        method_error(call(&client, OBJECT_PATH, INTERFACE, "Hello", &(2u32, "t")).await).0,
        "org.netvfs.Error.ProtocolError"
    );
    let reply = call(&client, OBJECT_PATH, INTERFACE, "Hello", &(1u32, "t")).await.unwrap();
    let (_, bridge, features): (u32, String, Vec<String>) = reply.body().deserialize().unwrap();
    assert_eq!((bridge.as_str(), features), (env!("CARGO_PKG_VERSION"), vec!["error-details".to_owned()]));
    let consent = call(&client, OBJECT_PATH, INTERFACE, "GetConsent", &()).await.unwrap();
    assert_eq!(consent.body().deserialize::<(String,)>().unwrap().0, "unknown");
    let locations = call(&client, OBJECT_PATH, INTERFACE, "ListLocations", &()).await.unwrap();
    assert_eq!(
        locations.body().deserialize::<(Vec<netvfs_bridge_proto::WireLocation>,)>().unwrap().0.len(),
        0
    );
    assert_eq!(
        method_error(call(&client, OBJECT_PATH, INTERFACE, "Disconnect", &("account:1",)).await),
        ("org.netvfs.Error.PermissionDenied".to_owned(), "No consent".to_owned())
    );
    assert_eq!(
        method_error(call(&client, OBJECT_PATH, INTERFACE, "Cancel", &(3u32,)).await),
        ("org.netvfs.Error.Internal".to_owned(), "The request was dropped".to_owned())
    );
    // Only valid calls after Hello reach the core.
    for name in ["Hello", "Hello", "GetConsent", "ListLocations", "Disconnect", "Cancel"] {
        assert!(matches!(next(&mut seen).await, Seen::Call(SID, n) if n == name), "{name}");
    }
    drop(client);
    closed(&mut seen).await;
    tokio::time::timeout(WAIT, session).await.unwrap().unwrap();
}

/// `Upload` brings its descriptor (`h`) to the core.
#[tokio::test]
async fn descriptors_reach_the_core() {
    let (sink, mut seen) = stub_core();
    let (stream, _session) = start(sink);
    let client = zbus_client(stream).await;
    let _outbox = accepted(&mut seen).await;
    call(&client, OBJECT_PATH, INTERFACE, "Hello", &(1u32, "t")).await.unwrap();
    let dir = crate::test_support::TempDir::new();
    let path = dir.path().join("data");
    std::fs::write(&path, b"twelve bytes").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let opts = std::collections::HashMap::<&str, zbus::zvariant::Value<'_>>::new();
    let body = ("account:1", b"/up".as_slice(), Fd::from(file.as_fd()), opts);
    let reply = call(&client, OBJECT_PATH, INTERFACE, "Upload", &body).await.unwrap();
    assert_eq!(reply.body().deserialize::<(u32,)>().unwrap().0, 12);
}

/// A message declaring more than 2 MiB closes the connection without
/// waiting for its body.
#[tokio::test]
async fn an_oversized_message_closes_the_session() {
    let (sink, mut seen) = stub_core();
    let (stream, session) = start(sink);
    let mut client = RawClient::authenticate(stream).await;
    client.begin_with(&[&hello()]).await;
    let _outbox = accepted(&mut seen).await;
    let reply = tokio::time::timeout(WAIT, client.receive()).await.unwrap().unwrap();
    assert_eq!(reply.message_type(), Type::MethodReturn);
    let big = bridge_call("Hello", &(1u32, "x".repeat(inbound::MAX_MESSAGE_BYTES)));
    client.write(&big.data()[..64]).await;
    assert!(client.closed_within(WAIT).await);
    closed(&mut seen).await;
    tokio::time::timeout(WAIT, session).await.unwrap().unwrap();
}

/// A consumer that sends calls but never reads the replies is throttled by
/// its own socket: the session stops reading.
#[tokio::test]
async fn unread_replies_throttle_the_reader() {
    let (sink, mut seen) = stub_core();
    let (stream, _session) = start(sink);
    let mut client = RawClient::authenticate(stream).await;
    client.begin_with(&[&hello()]).await;
    let outbox = accepted(&mut seen).await;
    let ping = Message::method_call("/", "Ping").unwrap().interface("org.freedesktop.DBus.Peer").unwrap();
    let ping = ping.build(&()).unwrap();
    let count = 50_000;
    let flood: Vec<u8> = std::iter::repeat_n(&ping.data()[..], count).flatten().copied().collect();
    let (mut read, mut write) = client.stream.into_split();
    let writer = tokio::spawn(async move {
        tokio::io::AsyncWriteExt::write_all(&mut write, &flood).await.unwrap();
        write
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!writer.is_finished(), "the session read everything without the replies being read");
    assert!(!outbox.is_closed());
    // Reading the replies lets the rest through.
    for _ in 0..=count {
        let reply = tokio::time::timeout(WAIT, read_message(&mut read)).await.unwrap().unwrap();
        assert_eq!(reply.message_type(), Type::MethodReturn);
    }
    let _write = tokio::time::timeout(WAIT, writer).await.unwrap().unwrap();
}

/// C-10: a consumer that never reads holds at most the flow budget of
/// streamed batches; cancellation and disconnection free a blocked
/// producer within a second.
#[tokio::test]
async fn flow_control_bounded() {
    let (sink, mut seen) = stub_core();
    let (stream, session) = start(sink);
    let mut client = RawClient::authenticate(stream).await;
    client.begin_with(&[&hello()]).await;
    let outbox = accepted(&mut seen).await;
    assert!(matches!(next(&mut seen).await, Seen::Call(SID, "Hello")));
    let batch = OutSignal::ListBatch { request: 1, entries: vec![wire_entry(); 512] };
    let bytes = batch.build().unwrap().data().len();
    let before = resident_bytes();

    let producer = |cancel: Arc<AtomicBool>, sent: Arc<AtomicUsize>| {
        let (outbox, batch) = (outbox.clone(), batch.clone());
        let (done, finished) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            while outbox.stream(&batch, bytes, &cancel) {
                sent.fetch_add(1, Ordering::SeqCst);
            }
            done.send(Instant::now()).ok();
        });
        finished
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let mut finished = producer(Arc::clone(&cancel), Arc::clone(&sent));
    // Saturated once the budget is spent and nothing more gets through for
    // a while (a slow machine, qemu, may take long for the first batch).
    let deadline = Instant::now() + Duration::from_mins(1);
    while outbox.flow().in_flight() <= FLOW_LIMIT {
        assert!(Instant::now() < deadline, "{} batches sent", sent.load(Ordering::SeqCst));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut last = usize::MAX;
    while sent.load(Ordering::SeqCst) != last {
        last = sent.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(last * bytes > FLOW_LIMIT, "{last} batches of {bytes} bytes");
    let in_flight = outbox.flow().in_flight();
    assert!(in_flight > FLOW_LIMIT && in_flight <= FLOW_LIMIT + bytes, "{in_flight}");
    // The resident set is the whole process's: this test needs a process of
    // its own, as cargo nextest gives every test (tools/ci/cross-build.sh
    // runs it alone); next to the other tests of a plain `cargo test` their
    // memory counts as well.
    // Under AddressSanitizer freed memory stays resident in its quarantine,
    // so the resident set says nothing there (rust-sanitize.sh sets the
    // variable); the budget above bounds what is queued all the same.
    if std::env::var_os("NETVFS_TEST_SANITIZER").is_none() {
        let growth = resident_bytes().saturating_sub(before);
        assert!(growth < 16 << 20, "resident set grew by {growth} bytes");
    }
    assert!(finished.try_recv().is_err());

    let canceled = Instant::now();
    cancel.store(true, Ordering::SeqCst);
    let at = tokio::time::timeout(Duration::from_secs(1), finished).await.unwrap().unwrap();
    assert!(at.duration_since(canceled) < Duration::from_secs(1));

    // A second producer blocks, until the consumer goes away.
    let finished = producer(Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let gone = Instant::now();
    drop(client);
    let at = tokio::time::timeout(Duration::from_secs(1), finished).await.unwrap().unwrap();
    assert!(at.duration_since(gone) < Duration::from_secs(1));
    closed(&mut seen).await;
    tokio::time::timeout(WAIT, session).await.unwrap().unwrap();
    assert!(outbox.is_closed());
    assert!(outbox.flow().is_closed());
    assert_eq!(outbox.flow().in_flight(), 0);
}

/// XB-6 revocation: the core closes the session, also while its writer is
/// stuck on a consumer that does not read.
#[tokio::test]
async fn the_core_closes_a_session() {
    let (sink, mut seen) = stub_core();
    let (stream, session) = start(sink);
    let mut client = RawClient::authenticate(stream).await;
    client.begin_with(&[&hello()]).await;
    let outbox = accepted(&mut seen).await;
    let batch = OutSignal::ListBatch { request: 1, entries: vec![wire_entry(); 512] };
    for _ in 0..40 {
        assert!(outbox.send_streamed(&batch, 0));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    outbox.close();
    closed(&mut seen).await;
    tokio::time::timeout(Duration::from_secs(1), session).await.unwrap().unwrap();
    assert!(!outbox.signal(&OutSignal::LocationsChanged));
    assert!(client.closed_within(WAIT).await);
}

/// A failed handshake reports nothing.
#[tokio::test]
async fn a_failed_handshake_is_silent() {
    let (sink, mut seen) = stub_core();
    let (stream, session) = start(sink);
    let mut client = RawClient { stream };
    client.write(b"\0AUTH NONSENSE\r\nBEGIN\r\n").await;
    drop(client);
    tokio::time::timeout(WAIT, session).await.unwrap().unwrap();
    assert!(seen.try_recv().is_err());
}
