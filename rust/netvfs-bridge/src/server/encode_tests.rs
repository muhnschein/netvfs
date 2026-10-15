// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs 0.4's C++ tst_bridgeunits wireRoundTrip (entries, maps, NUL in strings) and
// errorReplies; the reply and signal signatures against the method table.
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    BRIDGE_VERSION, ErrorName, HashMap, INTERFACE, INVALID_ARGS, Message, OBJECT_PATH, OutSignal, OwnedValue,
    Reply, Status, UNKNOWN_METHOD, Value, WireCapabilities, WireEntry, WireLocation, WireNearby,
    WireWalkItem, error_name, error_reply, status_extra, wire_entry, wire_text, wire_text_from_bytes,
};
use netvfs_bridge_proto::methods::{ENTRY_SIGNATURE, METHODS, SIGNALS, find_signal};
use netvfs_bridge_proto::{
    OptsBuilder, entry_flags, entry_kind, value_bytes, value_i64, value_str, value_strings,
};
use std::num::NonZeroU32;

fn call(serial: u32) -> Message {
    Message::method_call(OBJECT_PATH, "Stat")
        .unwrap()
        .interface(INTERFACE)
        .unwrap()
        .serial(NonZeroU32::new(serial).unwrap())
        .build(&())
        .unwrap()
}

fn entry() -> WireEntry {
    WireEntry {
        name: b"n\xff".to_vec(),
        kind: entry_kind::SYMLINK,
        target_kind: entry_kind::DIRECTORY,
        size: 42,
        mtime_ms: 1234,
        ctime_ms: -1,
        atime_ms: -1,
        mode: 0o755,
        uid: 7,
        gid: -1,
        owner: "o\0".to_owned(),
        group: "g\0".to_owned(),
        flags: entry_flags::HIDDEN | entry_flags::NAME_NOT_UTF8,
        etag: b"e".to_vec(),
        content_type: "text/\0plain".to_owned(),
    }
}

fn all_replies() -> Vec<Reply> {
    vec![
        Reply::Empty,
        Reply::Hello,
        Reply::Text("granted".to_owned()),
        Reply::Locations(vec![]),
        Reply::Capabilities(WireCapabilities::default()),
        Reply::Id(3),
        Reply::Entry(entry()),
        Reply::Bytes(b"x".to_vec()),
        Reply::Space { free: 1, total: 2, used: 3 },
        Reply::Opened { handle: 4, size: 5 },
    ]
}

#[test]
fn reply_signatures_cover_the_method_table() {
    let replies = all_replies();
    for reply in &replies {
        let msg = reply.build(&call(9).header()).unwrap();
        assert_eq!(msg.message_type(), zbus::message::Type::MethodReturn);
        assert_eq!(msg.header().reply_serial(), NonZeroU32::new(9));
        assert!(*msg.body().signature() == reply.signature(), "{reply:?}");
    }
    for method in &METHODS {
        assert!(replies.iter().any(|r| r.signature() == method.output), "no reply for {}", method.name);
    }
    assert_eq!(Reply::Entry(entry()).signature(), ENTRY_SIGNATURE);
}

#[test]
fn entry_and_map_round_trip() {
    let msg = Reply::Entry(entry()).build(&call(1).header()).unwrap();
    let (back,): (WireEntry,) = msg.body().deserialize().unwrap();
    // NUL cannot be on the wire (it would break the peer): U+FFFD instead.
    assert_eq!(
        back,
        WireEntry {
            owner: "o\u{fffd}".to_owned(),
            group: "g\u{fffd}".to_owned(),
            content_type: "text/\u{fffd}plain".to_owned(),
            ..entry()
        }
    );
    assert_eq!(wire_entry(&entry()), back);
    assert_eq!(wire_text_from_bytes(b"a\xffb\0"), "a\u{fffd}b\u{fffd}");
    assert_eq!(wire_text("plain"), "plain");

    let extra = OptsBuilder::new()
        .int("x", 5)
        .str("s", "t")
        .bool("b", true)
        .bytes("ay", b"z")
        .build_owned()
        .into_iter()
        .chain([("as".to_owned(), OwnedValue::try_from(Value::from(vec!["p", "q"])).unwrap())])
        .collect::<HashMap<_, _>>();
    let signal = OutSignal::JobFinished { job: 2, result: Ok(()), extra };
    let msg = signal.build().unwrap();
    let (job, name, message, map): (u32, String, String, HashMap<String, OwnedValue>) =
        msg.body().deserialize().unwrap();
    assert_eq!((job, name.as_str(), message.as_str()), (2, "", ""));
    assert_eq!(map.len(), 5);
    assert_eq!(value_i64(&map["x"]), Some(5));
    assert_eq!(value_str(&map["s"]).as_deref(), Some("t"));
    assert_eq!(value_bytes(&map["ay"]), Some(b"z".to_vec()));
    assert_eq!(value_strings(&map["as"]), Some(vec!["p".to_owned(), "q".to_owned()]));
}

#[test]
fn error_reply_name_message_extra() {
    let status =
        Status::new(ErrorName::TooManyConnections, "busy").with_detail("d").with_retry_after_ms(1500);
    let reply = error_reply(&call(7).header(), ErrorName::NotFound.dbus_name(), &status).unwrap();
    assert_eq!(reply.message_type(), zbus::message::Type::Error);
    assert_eq!(reply.header().error_name().unwrap().as_str(), "org.netvfs.Error.NotFound");
    assert_eq!(reply.header().reply_serial(), NonZeroU32::new(7));
    let (text, extra): (String, HashMap<String, OwnedValue>) = reply.body().deserialize().unwrap();
    assert_eq!(text, "busy");
    assert_eq!(value_i64(&extra["retryAfterMs"]), Some(1500));
    assert_eq!(value_str(&extra["detail"]).as_deref(), Some("d"));
    // Without details: the message only; an empty message is the bare name.
    let plain = error_reply(&call(8).header(), INVALID_ARGS, &Status::invalid_args("")).unwrap();
    assert_eq!(*plain.body().signature(), "s");
    assert_eq!(plain.body().deserialize::<(String,)>().unwrap().0, "InvalidArgs");
    let retry_only = error_reply(
        &call(8).header(),
        "org.netvfs.Error.Locked",
        &Status::new(ErrorName::Locked, "x").with_retry_after_ms(0),
    )
    .unwrap();
    let (_, extra): (String, HashMap<String, OwnedValue>) = retry_only.body().deserialize().unwrap();
    assert_eq!(extra.len(), 1);
    assert_eq!(value_i64(&extra["retryAfterMs"]), Some(0));
    assert!(error_reply(&call(8).header(), "not an error name", &status).is_err());

    assert_eq!(error_name(&Status::invalid_args("x"), true), INVALID_ARGS);
    assert_eq!(error_name(&Status::new(ErrorName::Unsupported, "x"), true), UNKNOWN_METHOD);
    assert_eq!(error_name(&Status::invalid_name("x"), true), "org.netvfs.Error.InvalidName");
    assert_eq!(error_name(&Status::invalid_args("x"), false), "org.netvfs.Error.ProtocolError");
    assert_eq!(error_name(&Status::new(ErrorName::Unsupported, "x"), false), "org.netvfs.Error.Unsupported");
}

#[test]
fn reply_values() {
    let call_msg = call(1);
    let header = call_msg.header();
    let hello = Reply::Hello.build(&header).unwrap();
    let (bridge,): (String,) = hello.body().deserialize().unwrap();
    assert_eq!(bridge, BRIDGE_VERSION);
    let text = Reply::Text("a\0".to_owned()).build(&header).unwrap();
    assert_eq!(text.body().deserialize::<(String,)>().unwrap().0, "a\u{fffd}");
    let caps = WireCapabilities {
        flags: vec!["A\0".to_owned()],
        checksum_algorithms: vec!["md5".to_owned()],
        max_name_bytes: 255,
    };
    let (back,): (WireCapabilities,) =
        Reply::Capabilities(caps).build(&header).unwrap().body().deserialize().unwrap();
    assert_eq!(
        back,
        WireCapabilities {
            flags: vec!["A\u{fffd}".to_owned()],
            checksum_algorithms: vec!["md5".to_owned()],
            max_name_bytes: 255
        }
    );
    let location = WireLocation {
        id: "account:1".to_owned(),
        provider: "fake".to_owned(),
        name: "N\0".to_owned(),
        info: OptsBuilder::new().str("kind", "account").build_owned(),
    };
    let (list,): (Vec<WireLocation>,) =
        Reply::Locations(vec![location]).build(&header).unwrap().body().deserialize().unwrap();
    assert_eq!(
        (list[0].id.as_str(), list[0].provider.as_str(), list[0].name.as_str()),
        ("account:1", "fake", "N\u{fffd}")
    );
    assert_eq!(value_str(&list[0].info["kind"]).as_deref(), Some("account"));
    assert_eq!(Reply::Id(3).build(&header).unwrap().body().deserialize::<(u32,)>().unwrap(), (3,));
    assert_eq!(
        Reply::Bytes(b"\0x".to_vec()).build(&header).unwrap().body().deserialize::<(Vec<u8>,)>().unwrap().0,
        b"\0x"
    );
    let space = Reply::Space { free: 1, total: 2, used: -1 }.build(&header).unwrap();
    assert_eq!(space.body().deserialize::<(i64, i64, i64)>().unwrap(), (1, 2, -1));
    let opened = Reply::Opened { handle: 4, size: -1 }.build(&header).unwrap();
    assert_eq!(opened.body().deserialize::<(u32, i64)>().unwrap(), (4, -1));
}

fn all_signals() -> Vec<OutSignal> {
    let nearby =
        WireNearby { name: "n\0".to_owned(), provider: "smb".to_owned(), host: "h".to_owned(), port: 445 };
    vec![
        OutSignal::ConsentChanged("granted".to_owned()),
        OutSignal::LocationsChanged,
        OutSignal::NearbyChanged(vec![nearby]),
        OutSignal::ListBatch { request: 1, entries: vec![entry()] },
        OutSignal::ListDone { request: 1, result: Err(Status::new(ErrorName::NotFound, "gone")) },
        OutSignal::JobProgress { job: 2, done: 3, total: -1 },
        OutSignal::WalkBatch { job: 2, items: vec![WireWalkItem { path: b"a/b".to_vec(), entry: entry() }] },
        OutSignal::JobFinished { job: 2, result: Ok(()), extra: HashMap::new() },
        OutSignal::Question {
            id: "q1".to_owned(),
            kind: "identity-unknown".to_owned(),
            details: HashMap::new(),
        },
    ]
}

#[test]
fn signals_match_the_table() {
    let signals = all_signals();
    assert_eq!(signals.iter().map(OutSignal::name).collect::<Vec<_>>(), SIGNALS.map(|(name, _)| name));
    for signal in &signals {
        let msg = signal.build().unwrap();
        let header = msg.header();
        assert_eq!(msg.message_type(), zbus::message::Type::Signal);
        assert_eq!(header.member().unwrap().as_str(), signal.name());
        assert_eq!(header.path().unwrap().as_str(), OBJECT_PATH);
        assert_eq!(header.interface().unwrap().as_str(), INTERFACE);
        assert!(*msg.body().signature() == find_signal(signal.name()).unwrap(), "{}", signal.name());
    }
}

#[test]
fn signal_values() {
    let decoded = |s: &OutSignal| s.build().unwrap();
    let consent = decoded(&OutSignal::ConsentChanged("de\0nied".to_owned()));
    assert_eq!(consent.body().deserialize::<(String,)>().unwrap().0, "de\u{fffd}nied");
    let done =
        decoded(&OutSignal::ListDone { request: 5, result: Err(Status::new(ErrorName::NotFound, "gone\0")) });
    assert_eq!(
        done.body().deserialize::<(u32, String, String)>().unwrap(),
        (5, "NotFound".to_owned(), "gone\u{fffd}".to_owned())
    );
    let ok = decoded(&OutSignal::ListDone { request: 6, result: Ok(()) });
    assert_eq!(ok.body().deserialize::<(u32, String, String)>().unwrap(), (6, String::new(), String::new()));
    let (req, entries): (u32, Vec<WireEntry>) =
        decoded(&OutSignal::ListBatch { request: 1, entries: vec![entry()] }).body().deserialize().unwrap();
    assert_eq!((req, entries[0].owner.as_str()), (1, "o\u{fffd}"));
    let (job, items): (u32, Vec<WireWalkItem>) = decoded(&OutSignal::WalkBatch {
        job: 3,
        items: vec![WireWalkItem { path: b"p".to_vec(), entry: entry() }],
    })
    .body()
    .deserialize()
    .unwrap();
    assert_eq!(
        (job, items[0].path.as_slice(), items[0].entry.content_type.as_str()),
        (3, b"p".as_slice(), "text/\u{fffd}plain")
    );
    let progress = decoded(&OutSignal::JobProgress { job: 2, done: 3, total: 4 });
    assert_eq!(progress.body().deserialize::<(u32, i64, i64)>().unwrap(), (2, 3, 4));
    let nearby = decoded(&all_signals()[2]);
    let (items,): (Vec<WireNearby>,) = nearby.body().deserialize().unwrap();
    assert_eq!((items[0].name.as_str(), items[0].port), ("n\u{fffd}", 445));
    let details = OptsBuilder::new().str("host", "h").build_owned();
    let question = decoded(&OutSignal::Question { id: "q\0".to_owned(), kind: "k\0".to_owned(), details });
    let (id, kind, back): (String, String, HashMap<String, OwnedValue>) =
        question.body().deserialize().unwrap();
    assert_eq!((id.as_str(), kind.as_str()), ("q\u{fffd}", "k\u{fffd}"));
    assert_eq!(value_str(&back["host"]).as_deref(), Some("h"));
}

#[test]
fn job_finished_adds_the_status_details() {
    let extra = OptsBuilder::new().int("files", 3).str("detail", "from the job").build_owned();
    let failed = Status::new(ErrorName::RateLimited, "slow").with_detail("429").with_retry_after_ms(10);
    let msg = OutSignal::JobFinished { job: 1, result: Err(failed), extra: extra.clone() }.build().unwrap();
    let (_, name, message, map): (u32, String, String, HashMap<String, OwnedValue>) =
        msg.body().deserialize().unwrap();
    assert_eq!((name.as_str(), message.as_str()), ("RateLimited", "slow"));
    assert_eq!(value_i64(&map["files"]), Some(3));
    assert_eq!(value_str(&map["detail"]).as_deref(), Some("429"));
    assert_eq!(value_i64(&map["retryAfterMs"]), Some(10));
    // Without details the job's own values stay.
    let plain = OutSignal::JobFinished { job: 1, result: Err(Status::new(ErrorName::Canceled, "")), extra }
        .build()
        .unwrap();
    let (_, name, _, map): (u32, String, String, HashMap<String, OwnedValue>) =
        plain.body().deserialize().unwrap();
    assert_eq!(name, "Canceled");
    assert_eq!(value_str(&map["detail"]).as_deref(), Some("from the job"));
    assert!(!map.contains_key("retryAfterMs"));
    assert!(status_extra(&Status::new(ErrorName::Canceled, "")).is_empty());
}
