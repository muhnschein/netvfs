// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs 0.4's C++ tst_bridgeunits: signaturesAndCounts, paths, numbers, options,
// identifiers, secretsMovedAndWiped, and the decode limits (wireRoundTrip).
// Restriction lints that only add noise to tests (doc/RUST.md "Lints").
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    AdHocOpts, AttributeChanges, Call, CopyOpts, DECODE_MAX_ELEMENTS, Disposition, ErrorName, Lane,
    MAX_ANSWER_BYTES, MAX_ANSWERS, MAX_CALL_BODY, MAX_ID, MAX_OFFSET, MAX_PATH, MAX_READ, MAX_READ_AHEAD,
    MAX_SECRET, MAX_SHORT, MAX_TIME_MS, MAX_URL, MIN_TIME_MS, Message, SECURITY_PROFILES, Secret, Status,
    TransferOpts, Value, WalkOpts, Zeroizing, ad_hoc_option, decode, decoder, is_valid_location_id,
    is_valid_token, lane_hint, location_id,
};
use netvfs_bridge_proto::methods::{INTERFACE, METHODS, OBJECT_PATH};
use std::collections::HashMap;
use std::os::fd::AsFd as _;
use zbus::export::serde::Serialize;
use zbus::zvariant::{DynamicType, Fd, ObjectPath, Signature};

const LOC: &str = "account:1";

pub(crate) fn message<B: Serialize + DynamicType>(member: &str, body: &B) -> Message {
    Message::method_call(OBJECT_PATH, member).unwrap().interface(INTERFACE).unwrap().build(body).unwrap()
}

fn validate<B: Serialize + DynamicType>(member: &str, body: &B) -> Result<Call, Status> {
    decode(&message(member, body))
}

fn error<B: Serialize + DynamicType>(member: &str, body: &B) -> ErrorName {
    validate(member, body).unwrap_err().name
}

type Map<'a> = HashMap<&'a str, Value<'a>>;

fn map<'a>(pairs: &[(&'a str, Value<'a>)]) -> Map<'a> {
    pairs.iter().map(|(k, v)| (*k, v.try_clone().unwrap())).collect()
}

fn none() -> Map<'static> {
    HashMap::new()
}

fn null_fd() -> std::fs::File {
    std::fs::File::open("/dev/null").unwrap()
}

/// A valid message for every method of the table.
fn valid_message(name: &str) -> Message {
    let fd = null_fd();
    let fd = Fd::from(fd.as_fd());
    let p: &[u8] = b"a";
    match name {
        "Hello" => message(name, &(1u32, "x")),
        "GetConsent" | "RequestConsent" | "ListLocations" => message(name, &()),
        "Capabilities" | "Disconnect" | "ForgetAdHoc" | "OpenAccountSettings" => message(name, &(LOC,)),
        "ConnectAdHoc" => message(name, &("sftp://h/", p, none())),
        "Discover" => message(name, &(true,)),
        "List" => message(name, &(LOC, p, "", 0u32)),
        "Stat" => message(name, &(LOC, p, true, "")),
        "ReadLink" | "SpaceInfo" | "RemoveFile" | "RemoveDir" | "RemoveTree" => message(name, &(LOC, p)),
        "Checksum" => message(name, &(LOC, p, "sha256")),
        "MakeDir" => message(name, &(LOC, p, false)),
        "Rename" => message(name, &(LOC, p, p, false)),
        "SetAttributes" | "Walk" => message(name, &(LOC, p, none())),
        "MakeSymlink" | "MakeHardlink" => message(name, &(LOC, p, p)),
        "ServerCopy" => message(name, &(LOC, p, p, none())),
        "OpenRead" => message(name, &(LOC, p, "")),
        "Read" => message(name, &(1u32, 0i64, 1u32)),
        "ReadAhead" => message(name, &(1u32, 0i64, 1i64)),
        "Close" | "Cancel" => message(name, &(1u32,)),
        "Upload" | "Download" => message(name, &(LOC, p, fd, none())),
        "CopyAcross" => message(name, &(LOC, p, "account:2", p, none())),
        "Answer" => message(name, &("q1", none())),
        "AddAccount" => message(name, &("sftp",)),
        other => panic!("no body for {other}"),
    }
}

#[test]
fn every_method_decodes_to_its_variant() {
    for info in &METHODS {
        let call = decode(&valid_message(info.name)).unwrap_or_else(|e| panic!("{}: {e}", info.name));
        assert_eq!(call.name(), info.name);
        assert_eq!(call.method(), info);
        assert_eq!(call.lane(), info.lane, "{}", info.name);
        assert_eq!(call.needs_consent(), info.needs_consent);
        assert_eq!(decoder(info.name)(&valid_message(info.name).body()).unwrap().name(), info.name);
    }
    assert_eq!(
        decoder("Frobnicate")(&valid_message("Hello").body()).unwrap_err().name,
        ErrorName::Unsupported
    );
}

#[test]
fn signatures_and_counts() {
    assert!(
        matches!(validate("Hello", &(1u32, "x")).unwrap(), Call::Hello { protocol: 1, ref client } if client == "x")
    );
    let wrong = validate("Hello", &("x", 1u32)).unwrap_err();
    assert_eq!((wrong.name, wrong.message.as_str()), (ErrorName::ProtocolError, "Hello takes (us)"));
    assert_eq!(error("Hello", &(1u32,)), ErrorName::ProtocolError); // count
    assert_eq!(error("Hello", &(1u32, "x", 2u32)), ErrorName::ProtocolError);
    let zero = validate("Hello", &(0u32, "x")).unwrap_err();
    assert_eq!(zero.message, "Protocol version 0 does not exist");
    // Same values, other D-Bus types (object path, signature): only the
    // signature check refuses them.
    assert_eq!(error("Hello", &(1u32, ObjectPath::try_from("/x").unwrap())), ErrorName::ProtocolError);
    assert_eq!(error("Hello", &(1u32, Signature::try_from("s").unwrap())), ErrorName::ProtocolError);
    assert_eq!(error("Frobnicate", &()), ErrorName::Unsupported);
    let nameless = Message::method_call(OBJECT_PATH, "Hello").unwrap().build(&(1u32, "x")).unwrap();
    assert_eq!(decode(&nameless).unwrap().name(), "Hello");
    validate("Stat", &(LOC, b"a".as_slice(), true, "")).unwrap();
    // A Download whose "h" is not a file descriptor.
    assert_eq!(error("Download", &(LOC, b"a".as_slice(), 5i32, none())), ErrorName::ProtocolError);
    // An "h" whose index names no descriptor of the message.
    let fd = null_fd();
    let with_fd = message("Download", &(LOC, b"a".as_slice(), Fd::from(fd.as_fd()), none()));
    let stripped = crate::sys::frame::message_from_frame(
        with_fd.data().to_vec(),
        vec![],
        with_fd.data().context().endian(),
    )
    .unwrap();
    let malformed = decode(&stripped).unwrap_err();
    assert_eq!(malformed.name, ErrorName::ProtocolError);
    assert!(malformed.message.starts_with("Malformed arguments"), "{}", malformed.message);
}

#[test]
fn paths_of_one_and_two_path_calls() {
    let bad: [&[u8]; 4] = [b"docs/../etc", b"./a", b"a\0b", &[b'a'; MAX_PATH + 1]];
    for raw in bad {
        assert_eq!(error("RemoveFile", &(LOC, raw)), ErrorName::InvalidName);
        // Both paths of a two-path call are checked.
        assert_eq!(error("Rename", &(LOC, b"ok".as_slice(), raw, false)), ErrorName::InvalidName);
        assert_eq!(error("Rename", &(LOC, raw, b"ok".as_slice(), false)), ErrorName::InvalidName);
        assert_eq!(error("MakeHardlink", &(LOC, b"ok".as_slice(), raw)), ErrorName::InvalidName);
        assert_eq!(error("MakeHardlink", &(LOC, raw, b"ok".as_slice())), ErrorName::InvalidName);
        assert_eq!(error("ServerCopy", &(LOC, raw, b"ok".as_slice(), none())), ErrorName::InvalidName);
        assert_eq!(error("ServerCopy", &(LOC, b"ok".as_slice(), raw, none())), ErrorName::InvalidName);
        assert_eq!(error("CopyAcross", &(LOC, raw, LOC, b"ok".as_slice(), none())), ErrorName::InvalidName);
        assert_eq!(error("CopyAcross", &(LOC, b"ok".as_slice(), LOC, raw, none())), ErrorName::InvalidName);
        assert_eq!(error("MakeSymlink", &(LOC, b"t".as_slice(), raw)), ErrorName::InvalidName);
    }
    let Call::RemoveFile { path, .. } = validate("RemoveFile", &(LOC, b"/docs//a/".as_slice())).unwrap()
    else {
        panic!()
    };
    assert_eq!(path.as_bytes(), b"/docs/a");
    let Call::Rename { from, to, replace, .. } =
        validate("Rename", &(LOC, b"a/".as_slice(), b"//b".as_slice(), true)).unwrap()
    else {
        panic!()
    };
    assert_eq!((from.as_bytes(), to.as_bytes(), replace), (b"a".as_slice(), b"/b".as_slice(), true));
    // A path must be bytes, never a string (XB-9).
    assert_eq!(error("RemoveFile", &(LOC, "a")), ErrorName::ProtocolError);
}

#[test]
fn numbers() {
    let p = b"".as_slice();
    // List batch: 0 is the default, at most 512 (XB-17).
    assert!(matches!(validate("List", &(LOC, p, "", 0u32)).unwrap(), Call::List { batch: 256, .. }));
    assert!(matches!(validate("List", &(LOC, p, "", 512u32)).unwrap(), Call::List { batch: 512, .. }));
    assert!(matches!(validate("List", &(LOC, p, "", 1u32)).unwrap(), Call::List { batch: 1, .. }));
    let big = validate("List", &(LOC, p, "", 513u32)).unwrap_err();
    assert_eq!((big.name, big.message.as_str()), (ErrorName::ProtocolError, "Batch size above 512"));
    // Read: at most 1 MiB, offsets >= 0.
    assert!(matches!(validate("Read", &(1u32, 0i64, MAX_READ)).unwrap(), Call::Read { max: MAX_READ, .. }));
    assert_eq!(validate("Read", &(1u32, 0i64, MAX_READ + 1)).unwrap_err().message, "Read size above 1 MiB");
    assert_eq!(validate("Read", &(1u32, -1i64, 1u32)).unwrap_err().message, "Argument 2 is out of range");
    assert_eq!(error("Read", &(1u32, MAX_OFFSET + 1, 1u32)), ErrorName::ProtocolError);
    assert!(matches!(
        validate("Read", &(7u32, MAX_OFFSET, 1u32)).unwrap(),
        Call::Read { handle: 7, offset: MAX_OFFSET, max: 1 }
    ));
    // ReadAhead is a hint: capped, not refused.
    assert!(matches!(
        validate("ReadAhead", &(1u32, 3i64, 1i64 << 40)).unwrap(),
        Call::ReadAhead { handle: 1, offset: 3, bytes: MAX_READ_AHEAD }
    ));
    assert!(matches!(validate("ReadAhead", &(1u32, 0i64, 5i64)).unwrap(), Call::ReadAhead { bytes: 5, .. }));
    assert_eq!(
        validate("ReadAhead", &(1u32, 0i64, -5i64)).unwrap_err().message,
        "Argument 3 is out of range"
    );
    assert_eq!(
        validate("ReadAhead", &(1u32, -1i64, 5i64)).unwrap_err().message,
        "Argument 2 is out of range"
    );
    assert!(matches!(validate("Close", &(9u32,)).unwrap(), Call::Close { handle: 9 }));
    assert!(matches!(validate("Cancel", &(4u32,)).unwrap(), Call::Cancel { id: 4 }));
}

#[test]
fn attribute_options() {
    let p = b"a".as_slice();
    let opts = map(&[
        ("mode", Value::from(0o644i32)),
        ("mtimeMs", Value::from(1000i64)),
        ("atimeMs", Value::from(7u8)),
    ]);
    let Call::SetAttributes { changes, .. } = validate("SetAttributes", &(LOC, p, opts)).unwrap() else {
        panic!()
    };
    assert_eq!(changes, AttributeChanges { mode: Some(0o644), mtime_ms: Some(1000), atime_ms: Some(7) });
    let refuse =
        |pairs: &[(&str, Value<'_>)]| validate("SetAttributes", &(LOC, p, map(pairs))).unwrap_err().message;
    assert_eq!(refuse(&[("mode", Value::from(0o10000i32))]), "Option \"mode\" is out of range");
    assert_eq!(refuse(&[("mode", Value::from(-1i32))]), "Option \"mode\" is out of range");
    assert_eq!(refuse(&[("mode", Value::from("644"))]), "Option \"mode\" must be an integer");
    assert_eq!(refuse(&[("owner", Value::from(1i32))]), "Unknown option \"owner\""); // unknown keys are refused
    assert_eq!(refuse(&[("mtimeMs", Value::from(MAX_TIME_MS + 1))]), "Option \"mtimeMs\" is out of range");
    assert_eq!(refuse(&[("atimeMs", Value::from(MIN_TIME_MS - 1))]), "Option \"atimeMs\" is out of range");
    // The edges are allowed; every integer type is accepted, nested variants unwrapped.
    let edges = map(&[
        ("mode", Value::Value(Box::new(Value::Value(Box::new(Value::from(0o7777u16)))))),
        ("mtimeMs", Value::from(MIN_TIME_MS)),
        ("atimeMs", Value::from(u64::try_from(MAX_TIME_MS).unwrap())),
    ]);
    let Call::SetAttributes { changes, .. } = validate("SetAttributes", &(LOC, p, edges)).unwrap() else {
        panic!()
    };
    assert_eq!(
        changes,
        AttributeChanges { mode: Some(0o7777), mtime_ms: Some(MIN_TIME_MS), atime_ms: Some(MAX_TIME_MS) }
    );
    assert_eq!(refuse(&[("mode", Value::from(u64::MAX))]), "Option \"mode\" must be an integer");
    assert_eq!(refuse(&[("mode", Value::from(true))]), "Option \"mode\" must be an integer");
    assert_eq!(refuse(&[("mode", Value::from(-1i16))]), "Option \"mode\" is out of range");
    let small = validate("SetAttributes", &(LOC, p, map(&[("mode", Value::from(0o644i16))]))).unwrap();
    assert!(matches!(small, Call::SetAttributes { changes: AttributeChanges { mode: Some(0o644), .. }, .. }));
    // The first offending key in key order is reported.
    assert_eq!(refuse(&[("zzz", Value::from(1i32)), ("aaa", Value::from(1i32))]), "Unknown option \"aaa\"");
    let long_key = "k".repeat(300);
    assert_eq!(
        refuse(&[(long_key.as_str(), Value::from(1i32))]),
        format!("Unknown option \"{}\"", "k".repeat(256))
    );
}

#[test]
fn transfer_options() {
    let p = b"a".as_slice();
    let file = null_fd();
    let fd = || Fd::from(file.as_fd());
    let upload = map(&[
        ("offset", Value::from(10i64)),
        ("size", Value::from(5i64)),
        ("disposition", Value::from("resume")),
        ("createMode", Value::from(0o600i32)),
        ("lane", Value::from("stream")),
        ("mtimeMs", Value::from(99i64)),
    ]);
    let Call::Upload { opts, lane, .. } = validate("Upload", &(LOC, p, fd(), upload)).unwrap() else {
        panic!()
    };
    assert_eq!(
        opts,
        TransferOpts {
            offset: 10,
            size: 5,
            disposition: Disposition::Resume,
            create_mode: Some(0o600),
            mtime_ms: Some(99)
        }
    );
    assert_eq!(lane, Lane::Stream);
    let upload_err =
        |pairs: &[(&str, Value<'_>)]| validate("Upload", &(LOC, p, fd(), map(pairs))).unwrap_err().message;
    let download_err =
        |pairs: &[(&str, Value<'_>)]| validate("Download", &(LOC, p, fd(), map(pairs))).unwrap_err().message;
    assert_eq!(upload_err(&[("disposition", Value::from("resume"))]), "Resume needs an offset");
    assert_eq!(
        upload_err(&[("disposition", Value::from("append"))]),
        "Option \"disposition\" must be create, truncate or resume"
    );
    assert_eq!(
        upload_err(&[("disposition", Value::from(1i32))]),
        "Option \"disposition\" must be create, truncate or resume"
    );
    assert_eq!(upload_err(&[("size", Value::from(-2i64))]), "Option \"size\" is out of range");
    assert_eq!(upload_err(&[("offset", Value::from(-1i64))]), "Option \"offset\" is out of range");
    assert_eq!(upload_err(&[("offset", Value::from(MAX_OFFSET + 1))]), "Option \"offset\" is out of range");
    assert_eq!(upload_err(&[("size", Value::from(MAX_OFFSET + 1))]), "Option \"size\" is out of range");
    assert_eq!(upload_err(&[("lane", Value::from(1i32))]), "Option \"lane\" must be a string");
    assert_eq!(upload_err(&[("lane", Value::from("fast"))]), "Unknown lane");
    assert_eq!(
        upload_err(&[("createMode", Value::from(0o10000i32))]),
        "Option \"createMode\" is out of range"
    );
    assert_eq!(
        upload_err(&[("mtimeMs", Value::from(MAX_TIME_MS + 1))]),
        "Option \"mtimeMs\" is out of range"
    );
    let truncate = map(&[
        ("disposition", Value::from("truncate")),
        ("size", Value::from(-1i64)),
        ("lane", Value::from("")),
    ]);
    let Call::Upload { opts, lane, .. } = validate("Upload", &(LOC, p, fd(), truncate)).unwrap() else {
        panic!()
    };
    assert_eq!((opts.disposition, opts.size, lane), (Disposition::Truncate, -1, Lane::Bulk));
    let create = map(&[("disposition", Value::from("create"))]);
    let Call::Upload { opts, .. } = validate("Upload", &(LOC, p, fd(), create)).unwrap() else { panic!() };
    assert_eq!(opts, TransferOpts::default());
    // Write-only options are refused by Download.
    for key in ["createMode", "disposition", "mtimeMs"] {
        assert_eq!(download_err(&[(key, Value::from(0o600i32))]), format!("Unknown option \"{key}\""));
    }
    let Call::Download { opts, lane, .. } = validate(
        "Download",
        &(LOC, p, fd(), map(&[("offset", Value::from(7u32)), ("size", Value::from(3u8))])),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!((opts.offset, opts.size, lane), (7, 3, Lane::Bulk));
    assert_eq!(download_err(&[("offset", Value::from(u64::MAX))]), "Option \"offset\" must be an integer");
    let Call::Download { lane, .. } =
        validate("Download", &(LOC, p, fd(), map(&[("lane", Value::from("interactive"))]))).unwrap()
    else {
        panic!()
    };
    assert_eq!(lane, Lane::Interactive);
}

#[test]
fn tree_options() {
    let p = b"".as_slice();
    let walk = map(&[
        ("maxDepth", Value::from(3i32)),
        ("followSymlinks", Value::from(true)),
        ("postOrder", Value::from(true)),
    ]);
    let Call::Walk { opts, .. } = validate("Walk", &(LOC, p, walk)).unwrap() else { panic!() };
    assert_eq!(opts, WalkOpts { max_depth: 3, follow_symlinks: true, post_order: true });
    let Call::Walk { opts, .. } = validate("Walk", &(LOC, p, none())).unwrap() else { panic!() };
    assert_eq!(opts, WalkOpts::default());
    let walk_err = |pairs: &[(&str, Value<'_>)]| validate("Walk", &(LOC, p, map(pairs))).unwrap_err().message;
    assert_eq!(walk_err(&[("maxDepth", Value::from(5000i32))]), "Option \"maxDepth\" is out of range");
    assert_eq!(walk_err(&[("maxDepth", Value::from(-2i32))]), "Option \"maxDepth\" is out of range");
    assert!(validate("Walk", &(LOC, p, map(&[("maxDepth", Value::from(4096i32))]))).is_ok());
    assert!(validate("Walk", &(LOC, p, map(&[("maxDepth", Value::from(-1i32))]))).is_ok());
    assert_eq!(
        walk_err(&[("followSymlinks", Value::from(1i32))]),
        "Option \"followSymlinks\" must be a boolean"
    );
    assert_eq!(walk_err(&[("postOrder", Value::from("yes"))]), "Option \"postOrder\" must be a boolean");
    assert_eq!(walk_err(&[("depth", Value::from(1i32))]), "Unknown option \"depth\"");

    let copy = map(&[("recursive", Value::from(true)), ("replace", Value::from(true))]);
    let Call::ServerCopy { opts, .. } =
        validate("ServerCopy", &(LOC, b"a".as_slice(), b"b".as_slice(), copy)).unwrap()
    else {
        panic!()
    };
    assert_eq!(opts, CopyOpts { recursive: true, replace: true });
    let copy_err = |pairs: &[(&str, Value<'_>)]| {
        validate("ServerCopy", &(LOC, b"a".as_slice(), b"b".as_slice(), map(pairs))).unwrap_err().message
    };
    assert_eq!(copy_err(&[("recursive", Value::from(1i32))]), "Option \"recursive\" must be a boolean");
    assert_eq!(copy_err(&[("replace", Value::from(1i32))]), "Option \"replace\" must be a boolean");
    assert_eq!(copy_err(&[("force", Value::from(true))]), "Unknown option \"force\"");
    let Call::CopyAcross { loc, dest_loc, dest_path, opts, .. } = validate(
        "CopyAcross",
        &(LOC, b"a".as_slice(), "adhoc:2", b"b/".as_slice(), map(&[("replace", Value::from(true))])),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!((loc.as_str(), dest_loc.as_str(), dest_path.as_bytes()), (LOC, "adhoc:2", b"b".as_slice()));
    assert_eq!(opts, CopyOpts { recursive: false, replace: true });
    assert_eq!(
        error("CopyAcross", &(LOC, b"a".as_slice(), "Bad", b"b".as_slice(), none())),
        ErrorName::ProtocolError
    );
}

#[test]
fn lanes_and_links() {
    let p = b"a".as_slice();
    assert_eq!(validate("Stat", &(LOC, p, true, "fast")).unwrap_err().message, "Unknown lane");
    assert_eq!(validate("Stat", &(LOC, p, true, "bulk")).unwrap().lane(), Lane::Bulk);
    assert!(matches!(
        validate("Stat", &(LOC, p, false, "")).unwrap(),
        Call::Stat { follow: false, lane: Lane::Interactive, .. }
    ));
    assert_eq!(validate("List", &(LOC, p, "stream", 0u32)).unwrap().lane(), Lane::Stream);
    assert_eq!(error("List", &(LOC, p, "x", 0u32)), ErrorName::ProtocolError);
    assert_eq!(validate("OpenRead", &(LOC, p, "")).unwrap().lane(), Lane::Stream);
    assert_eq!(validate("OpenRead", &(LOC, p, "bulk")).unwrap().lane(), Lane::Bulk);
    assert_eq!(error("OpenRead", &(LOC, p, "x")), ErrorName::ProtocolError);
    assert!(matches!(validate("MakeDir", &(LOC, p, true)).unwrap(), Call::MakeDir { exclusive: true, .. }));
    assert!(matches!(validate("Discover", &(false,)).unwrap(), Call::Discover { on: false }));
    // Symlink targets are verbatim but bounded.
    let Call::MakeSymlink { target, link, .. } =
        validate("MakeSymlink", &(LOC, b"../x".as_slice(), b"l/".as_slice())).unwrap()
    else {
        panic!()
    };
    assert_eq!((target.as_slice(), link.as_bytes()), (b"../x".as_slice(), b"l".as_slice()));
    let target_err = |t: &[u8]| validate("MakeSymlink", &(LOC, t, b"l".as_slice())).unwrap_err();
    assert_eq!(target_err(b"").name, ErrorName::InvalidName);
    assert_eq!(target_err(b"a\0").message, "Invalid link target");
    assert_eq!(target_err(&[b'a'; MAX_PATH + 1]).name, ErrorName::InvalidName);
    assert!(validate("MakeSymlink", &(LOC, &[b'a'; MAX_PATH][..], b"l".as_slice())).is_ok());
}

#[test]
fn identifiers() {
    assert!(is_valid_location_id("account:12"));
    assert!(is_valid_location_id("adhoc:3"));
    assert!(is_valid_location_id("a-b"));
    assert!(!is_valid_location_id("Account:1"));
    assert!(!is_valid_location_id("a/b"));
    assert!(!is_valid_location_id(""));
    assert!(is_valid_location_id(&"a".repeat(MAX_ID)));
    assert!(!is_valid_location_id(&"a".repeat(MAX_ID + 1)));
    assert!(is_valid_token("sha256", 32));
    assert!(is_valid_token("x-1", 32));
    assert!(!is_valid_token("SHA256", 32));
    assert!(!is_valid_token("a:b", 32));
    assert!(!is_valid_token("", 32));
    assert!(is_valid_token(&"a".repeat(32), 32));
    assert!(!is_valid_token(&"a".repeat(33), 32));
    let checksum = validate("Checksum", &(LOC, b"a".as_slice(), "md 5")).unwrap_err();
    assert_eq!(checksum.message, "Argument 3 is not a valid name");
    assert_eq!(
        validate("Checksum", &(LOC, b"a".as_slice(), "a".repeat(33))).unwrap_err().message,
        "Argument 3 is too long"
    );
    assert!(
        matches!(validate("Checksum", &(LOC, b"a".as_slice(), "md5")).unwrap(), Call::Checksum { ref algorithm, .. } if algorithm == "md5")
    );
    assert_eq!(validate("AddAccount", &("../sftp",)).unwrap_err().message, "Argument 1 is not a valid name");
    assert!(
        matches!(validate("AddAccount", &("smb",)).unwrap(), Call::AddAccount { ref provider } if provider == "smb")
    );
    assert_eq!(validate("Capabilities", &("",)).unwrap_err().message, "Invalid location id");
    assert_eq!(error("Disconnect", &("a b",)), ErrorName::ProtocolError);
    assert_eq!(location_id("account:1".to_owned()).unwrap().as_str(), "account:1");
    assert_eq!(lane_hint("", Lane::Bulk).unwrap(), Lane::Bulk);
    // Hello's client name: at most 256 UTF-16 units.
    assert!(validate("Hello", &(1u32, "é".repeat(256))).is_ok());
    assert_eq!(validate("Hello", &(1u32, "x".repeat(257))).unwrap_err().message, "Argument 2 is too long");
    assert_eq!(validate("Hello", &(1u32, "😀".repeat(129))).unwrap_err().message, "Argument 2 is too long");
}

#[test]
fn ad_hoc_options() {
    let secret = b"s".as_slice();
    let opts = map(&[("user", Value::from("bob")), ("security_profile", Value::from("signed"))]);
    let Call::ConnectAdHoc { url, opts, .. } = validate("ConnectAdHoc", &("smb://h/", secret, opts)).unwrap()
    else {
        panic!()
    };
    assert_eq!(url, "smb://h/");
    assert_eq!(opts, AdHocOpts { user: Some("bob".to_owned()), security_profile: Some("signed".to_owned()) });
    let Call::ConnectAdHoc { opts, .. } =
        validate("ConnectAdHoc", &("smb://h/", secret, map(&[("user", Value::from(""))]))).unwrap()
    else {
        panic!()
    };
    assert_eq!(opts, AdHocOpts::default());
    let err = |pairs: &[(&str, Value<'_>)]| {
        validate("ConnectAdHoc", &("u", secret, map(pairs))).unwrap_err().message
    };
    assert_eq!(err(&[("user", Value::from(1i32))]), "Option \"user\" must be a short string");
    assert_eq!(err(&[("user", Value::from("u".repeat(257)))]), "Option \"user\" must be a short string");
    // zvariant refuses NUL in a string already; the check stays for values
    // built in memory.
    assert_eq!(
        error("ConnectAdHoc", &("u", secret, map(&[("user", Value::from("a\0b"))]))),
        ErrorName::ProtocolError
    );
    let nul = ad_hoc_option("user", &Value::from("a\0b"), &mut AdHocOpts::default()).unwrap_err();
    assert_eq!(nul.message, "Option \"user\" contains NUL");
    assert_eq!(err(&[("security_profile", Value::from("weak"))]), "Unknown security profile");
    // The type check comes first, as in args.cpp.
    assert_eq!(err(&[("other", Value::from(1i32))]), "Option \"other\" must be a short string");
    assert_eq!(err(&[("other", Value::from("x"))]), "Unknown option \"other\"");
    for profile in SECURITY_PROFILES {
        assert!(
            validate("ConnectAdHoc", &("u", secret, map(&[("security_profile", Value::from(profile))])))
                .is_ok()
        );
    }
    assert!(validate("ConnectAdHoc", &("u".repeat(MAX_URL), secret, none())).is_ok());
    assert_eq!(
        validate("ConnectAdHoc", &("u".repeat(MAX_URL + 1), secret, none())).unwrap_err().message,
        "Argument 1 is too long"
    );
}

#[test]
fn secrets_are_zeroizing() {
    let Call::ConnectAdHoc { secret, .. } =
        validate("ConnectAdHoc", &("sftp://h/", b"hunter2".as_slice(), none())).unwrap()
    else {
        panic!()
    };
    assert_eq!(secret.expose(), b"hunter2");
    // The only holder is the wiping container; Debug never shows it.
    assert_eq!(format!("{secret:?}"), "Secret(7 bytes)");
    let call = validate("ConnectAdHoc", &("sftp://h/", b"hunter2".as_slice(), none())).unwrap();
    assert!(!format!("{call:?}").contains("hunter2"));
    let wiping: Zeroizing<Vec<u8>> = secret.into_inner();
    assert_eq!(wiping.as_slice(), b"hunter2");

    let answers = map(&[("accept", Value::from(true)), ("answers", Value::from(vec![b"123456".to_vec()]))]);
    let call = validate("Answer", &("q1", answers)).unwrap();
    assert!(!format!("{call:?}").contains("123456"));
    let Call::Answer { id, accept, answers } = call else { panic!() };
    assert_eq!((id.as_str(), accept, answers.len()), ("q1", true, 1));
    assert_eq!(answers[0].expose(), b"123456");

    let too_long = vec![b'x'; MAX_SECRET + 1];
    assert_eq!(
        validate("ConnectAdHoc", &("sftp://h/", too_long.as_slice(), none())).unwrap_err().message,
        "Secret too long"
    );
    assert!(validate("ConnectAdHoc", &("sftp://h/", &too_long[1..], none())).is_ok());
    // The largest legitimate call fits the body limit.
    let url = "\u{ffff}".repeat(MAX_URL);
    let big = map(&[
        ("user", Value::from("\u{ffff}".repeat(MAX_SHORT))),
        ("security_profile", Value::from("strict")),
    ]);
    assert!(validate("ConnectAdHoc", &(url, &too_long[1..], big)).is_ok());
}

#[test]
fn body_size_limit() {
    let p = b"a".as_slice();
    let bytes = |n: usize| map(&[("mode", Value::from(vec![1u8; n]))]);
    // Just at the limit: decoded (and refused for its type).
    let at_limit = message("SetAttributes", &(LOC, p, bytes(1)));
    let overhead = at_limit.body().len() - 1;
    let fits = validate("SetAttributes", &(LOC, p, bytes(MAX_CALL_BODY - overhead))).unwrap_err();
    assert_eq!(fits.message, "Option \"mode\" must be an integer");
    let over = validate("SetAttributes", &(LOC, p, bytes(MAX_CALL_BODY - overhead + 1))).unwrap_err();
    assert_eq!((over.name, over.message.as_str()), (ErrorName::ProtocolError, "Arguments too large"));
}

#[test]
fn answers() {
    let answer = |opts: Map<'_>| validate("Answer", &("q7", opts));
    let message = |opts: Map<'_>| answer(opts).unwrap_err().message;
    // av of ay works as aay does; nested variants are unwrapped.
    let av = Value::from(vec![Value::Value(Box::new(Value::from(b"a".to_vec()))), Value::from(b"".to_vec())]);
    let Call::Answer { accept, answers, .. } = answer(map(&[("answers", av)])).unwrap() else { panic!() };
    assert!(!accept);
    assert_eq!(answers.iter().map(Secret::expose).collect::<Vec<_>>(), [b"a".as_slice(), b"".as_slice()]);
    let empty: Vec<Vec<u8>> = vec![];
    assert!(answer(map(&[("answers", Value::from(empty))])).is_ok());
    let must = "Option \"answers\" must be an array of byte arrays";
    assert_eq!(message(map(&[("answers", Value::from(b"ab".to_vec()))])), must);
    assert_eq!(message(map(&[("answers", Value::from(vec!["a"]))])), must);
    let no_strings: Vec<String> = vec![];
    assert_eq!(message(map(&[("answers", Value::from(no_strings))])), must);
    assert_eq!(message(map(&[("answers", Value::from(1i32))])), must);
    assert_eq!(
        message(map(&[("answers", Value::from(vec![vec![1u8]; MAX_ANSWERS + 1]))])),
        "Too many answers"
    );
    assert!(answer(map(&[("answers", Value::from(vec![vec![1u8]; MAX_ANSWERS]))])).is_ok());
    assert_eq!(
        message(map(&[("answers", Value::from(vec![vec![1u8; MAX_ANSWER_BYTES + 1]]))])),
        "Invalid answer"
    );
    assert!(answer(map(&[("answers", Value::from(vec![vec![1u8; MAX_ANSWER_BYTES]]))])).is_ok());
    // The C++ Limits::MaxShortString * 4.
    assert_eq!(MAX_ANSWER_BYTES, 1024);
    assert_eq!(message(map(&[("answers", Value::from(vec![Value::from(1i32)]))])), "Invalid answer");
    assert_eq!(message(map(&[("answers", Value::from(vec![vec![1u16]]))])), "Invalid answer");
    assert_eq!(message(map(&[("accept", Value::from("yes"))])), "Option \"accept\" must be a boolean");
    assert_eq!(message(map(&[("reason", Value::from(true))])), "Unknown option \"reason\"");
    assert_eq!(validate("Answer", &("Q1", none())).unwrap_err().message, "Invalid question id");
    assert_eq!(validate("Answer", &("q".repeat(65), none())).unwrap_err().message, "Argument 1 is too long");
}

/// Six and seven levels of arrays around an int.
fn six_levels() -> Value<'static> {
    Value::from(vec![vec![vec![vec![vec![vec![1i32]]]]]])
}

fn seven_levels() -> Value<'static> {
    Value::from(vec![vec![vec![vec![vec![vec![vec![1i32]]]]]]])
}

#[test]
fn variant_depth_and_element_limits() {
    let p = b"a".as_slice();
    let opts = |v: Value<'static>| map(&[("mode", v)]);
    // The C++ decoder: a{sv} (depth 0) > dict (1) > variant (1) > value (2):
    // six more levels fit.
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(six_levels()))).unwrap_err().message,
        "Option \"mode\" must be an integer"
    );
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(seven_levels()))).unwrap_err().message,
        "Argument too complex"
    );
    let mut deep_variant = Value::from(1i32);
    for _ in 0..7 {
        deep_variant = Value::Value(Box::new(deep_variant));
    }
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(deep_variant))).unwrap_err().message,
        "Argument too complex"
    );
    let mut ok_variant = Value::from(0o644i32);
    for _ in 0..5 {
        ok_variant = Value::Value(Box::new(ok_variant));
    }
    assert!(validate("SetAttributes", &(LOC, p, opts(ok_variant))).is_ok());
    // Elements per container.
    let many = Value::from(vec![1i32; DECODE_MAX_ELEMENTS + 1]);
    assert_eq!(validate("SetAttributes", &(LOC, p, opts(many))).unwrap_err().message, "Argument too complex");
    let fits = Value::from(vec![1i32; DECODE_MAX_ELEMENTS]);
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(fits))).unwrap_err().message,
        "Option \"mode\" must be an integer"
    );
    // Byte arrays do not count.
    let bytes = Value::from(vec![1u8; DECODE_MAX_ELEMENTS + 1]);
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(bytes))).unwrap_err().message,
        "Option \"mode\" must be an integer"
    );
    let dict: HashMap<String, i32> = (0..=DECODE_MAX_ELEMENTS).map(|i| (i.to_string(), 1)).collect();
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(Value::from(dict)))).unwrap_err().message,
        "Argument too complex"
    );
    let structure = Value::from((1i32, six_levels()));
    assert_eq!(
        validate("SetAttributes", &(LOC, p, opts(structure))).unwrap_err().message,
        "Argument too complex"
    );
    let names: Vec<String> = (0..=DECODE_MAX_ELEMENTS).map(|i| i.to_string()).collect();
    let keys: Map<'_> = names.iter().map(|k| (k.as_str(), Value::from(1i32))).collect();
    assert_eq!(validate("SetAttributes", &(LOC, p, keys)).unwrap_err().message, "Argument too complex");
    // Exactly the limit: counted in, then refused for the unknown key.
    let keys: Map<'_> = names[1..].iter().map(|k| (k.as_str(), Value::from(1i32))).collect();
    assert_eq!(keys.len(), DECODE_MAX_ELEMENTS);
    assert!(validate("SetAttributes", &(LOC, p, keys)).unwrap_err().message.starts_with("Unknown option"));
}
