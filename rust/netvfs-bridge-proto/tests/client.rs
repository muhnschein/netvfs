// SPDX-License-Identifier: LGPL-2.1-or-later
//! The client side of the protocol against the fake: errors with details,
//! malformed calls, ordered signals, disconnects and secret handling
//! (SPEC-v2 XB-3, XB-9, XB-16).
// Test helpers outside #[test] functions: a failing test is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "fake")]

use futures_lite::StreamExt as _;
use netvfs_bridge_proto::fake::{Failure, FakeBridge, RecordedAnswer};
use netvfs_bridge_proto::{BridgeError, OptsBuilder, Signal, SignalStream, Zeroizing, connect};
use std::time::Duration;

/// A fresh folder below the temporary one, removed on drop.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("netvfs-bridge-proto-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

async fn fake_with_account() -> FakeBridge {
    let fake = FakeBridge::new();
    fake.add_account(1, "fake", "Fake 1", "fake.example").await;
    fake
}

async fn hello(conn: &netvfs_bridge_proto::Connection) {
    conn.proxy().hello("test").await.unwrap();
}

/// The next signal; fails after five seconds instead of waiting forever.
async fn next_signal(signals: &mut SignalStream) -> Signal {
    tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("no signal within five seconds")
        .expect("the stream ended")
        .unwrap()
}

#[tokio::test]
async fn connects_to_a_socket_path_without_a_bus() {
    let dir = TempDir::new("socket-path");
    let path = dir.0.join("netvfs/bridge.sock");
    let fake = fake_with_account().await;
    let _listener = fake.listen(&path).unwrap();
    let conn = connect(&path).await.unwrap();
    let version = conn.proxy().hello("test").await.unwrap();
    assert_eq!(version, "0.2.0-fake");
    let locations = conn.proxy().list_locations().await.unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!((locations[0].id.as_str(), locations[0].provider.as_str()), ("account:1", "fake"));
}

#[tokio::test]
async fn a_missing_socket_is_a_disconnect() {
    let dir = TempDir::new("missing-socket");
    let e = connect(&dir.0.join("none.sock")).await.err().unwrap();
    assert!(matches!(e, BridgeError::Disconnected(_)), "{e:?}");
}

#[tokio::test]
async fn errors_carry_name_message_detail_and_retry_hint() {
    let fake = fake_with_account().await;
    fake.put_file("account:1", b"f", b"x");
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;

    fake.fail(Failure::new("Stat", "RateLimited", "slow down").detail("HTTP 429").retry_after(1500).times(1));
    let e = BridgeError::from(conn.proxy().stat("account:1", b"f", true, "").await.unwrap_err());
    match e {
        BridgeError::Remote { name, message, detail, retry_after_ms } => {
            assert_eq!(name, "org.netvfs.Error.RateLimited");
            assert_eq!(message, "slow down");
            assert_eq!(detail.as_deref(), Some("HTTP 429"));
            assert_eq!(retry_after_ms, Some(1500));
        }
        other => panic!("unexpected {other:?}"),
    }

    // Without details the second argument is absent and the message still reads.
    let e = BridgeError::from(conn.proxy().stat("account:1", b"missing", true, "").await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("NotFound"));
    match e {
        BridgeError::Remote { detail, retry_after_ms, .. } => {
            assert_eq!((detail, retry_after_ms), (None, None));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn malformed_calls_are_invalid_args() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    let p = conn.proxy();
    let invalid = |e: zbus::Error| matches!(BridgeError::from(e), BridgeError::InvalidArgs(_));
    assert!(invalid(p.stat("account:1", b"", true, "fast").await.unwrap_err()));
    assert!(invalid(p.stat("no such", b"", true, "").await.unwrap_err()));
    assert!(invalid(p.list("account:1", b"", "", 513).await.unwrap_err()));
    assert!(invalid(p.read(1, 0, (1 << 20) + 1).await.unwrap_err()));
    assert!(invalid(p.read(1, -1, 1).await.unwrap_err()));
    let bad_opts = OptsBuilder::new().str("owner", "root").build();
    assert!(invalid(p.set_attributes("account:1", b"a", &bad_opts).await.unwrap_err()));
    // A path that climbs out is a name error, not an argument error.
    let e = BridgeError::from(p.stat("account:1", b"a/../b", true, "").await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("InvalidName"));
}

#[tokio::test]
async fn calls_before_hello_are_refused() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    let e = BridgeError::from(conn.proxy().list_locations().await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("ProtocolError"));
    hello(&conn).await;
    assert_eq!(conn.proxy().list_locations().await.unwrap().len(), 1);
}

#[tokio::test]
async fn listing_signals_arrive_in_order() {
    let fake = fake_with_account().await;
    for name in ["a", "b", "c"] {
        fake.put_file("account:1", name.as_bytes(), b"x");
    }
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    hello(&conn).await;
    let req = conn.proxy().list("account:1", b"", "", 1).await.unwrap();
    let mut names = Vec::new();
    loop {
        match next_signal(&mut signals).await {
            Signal::ListBatch { req: r, entries } => {
                assert_eq!(r, req);
                assert_eq!(entries.len(), 1, "batches of one were asked for");
                names.push(entries[0].name.clone());
            }
            Signal::ListDone { req: r, error, .. } => {
                assert_eq!((r, error.as_str()), (req, ""));
                break;
            }
            // The listing connected the location: its state is told.
            Signal::LocationsChanged => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        names,
        vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        "ListDone came after the last batch"
    );
}

#[tokio::test]
async fn the_signal_stream_ends_when_the_bridge_goes_away() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    hello(&conn).await;
    fake.disconnect_clients().await;
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match signals.next().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the stream never ended");
    assert!(signals.next().await.is_none(), "and stays ended");
    let e = BridgeError::from(conn.proxy().get_consent().await.unwrap_err());
    assert!(matches!(e, BridgeError::Disconnected(_)), "{e:?}");
}

#[tokio::test]
async fn the_secret_is_wiped_after_the_call_whatever_happens() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    let none = OptsBuilder::new().build();

    let mut secret = Zeroizing::new(b"hunter2".to_vec());
    let loc = conn.connect_ad_hoc_wiping("sftp://host/", &mut secret, &none).await.unwrap();
    assert_eq!(loc, "adhoc:1");
    assert!(secret.is_empty(), "wiped after success");
    assert_eq!(fake.received_secrets(), vec![b"hunter2".to_vec()], "the bridge did get it");

    let mut secret = Zeroizing::new(b"hunter3".to_vec());
    let e = conn.connect_ad_hoc_wiping("sftp://u:pw@host/", &mut secret, &none).await.unwrap_err();
    assert_eq!(e.netvfs_name(), Some("SecurityPolicy"));
    assert!(secret.is_empty(), "wiped after a refusal");

    // The caller gives up while the bridge is still working.
    fake.set_latency(Duration::from_secs(5));
    let mut secret = Zeroizing::new(b"hunter4".to_vec());
    let call = conn.connect_ad_hoc_wiping("sftp://host/", &mut secret, &none);
    tokio::time::timeout(Duration::from_millis(50), call).await.unwrap_err();
    assert!(secret.is_empty(), "wiped when the future is dropped");
}

#[tokio::test]
async fn keyboard_answers_are_wiped_after_the_call() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    let mut answers = Zeroizing::new(vec![b"123456".to_vec()]);
    // No such question: the bridge refuses, the answers are gone anyway.
    let e = conn.answer_wiping("q1", true, &mut answers).await.unwrap_err();
    assert_eq!(e.netvfs_name(), Some("NotFound"));
    assert!(answers.is_empty());
}

/// The id of the next `Question` signal; fails after five seconds.
async fn next_question(signals: &mut SignalStream) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Signal::Question { id, .. } = signals.next().await.unwrap().unwrap() {
                return id;
            }
        }
    })
    .await
    .expect("no Question signal")
}

#[tokio::test]
async fn keyboard_answers_reach_the_bridge_then_are_wiped() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    hello(&conn).await;
    let mut answers = Zeroizing::new(vec![b"123456".to_vec(), b"second".to_vec()]);
    let answering = async {
        let id = next_question(&mut signals).await;
        conn.answer_wiping(&id, true, &mut answers).await.unwrap();
        assert!(answers.is_empty(), "wiped after the answer was sent");
        id
    };
    let (asked, id) = tokio::join!(fake.ask("keyboard-interactive", Vec::new()), answering);
    let want = RecordedAnswer { id, accept: true, answers: vec![b"123456".to_vec(), b"second".to_vec()] };
    assert_eq!(asked, Some(want.clone()), "the bridge got the answers and the acceptance");
    assert_eq!(fake.answers(), vec![want]);
}

#[tokio::test]
async fn a_connection_debugs_as_its_type() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    assert_eq!(format!("{conn:?}"), "Connection");
}

#[tokio::test]
async fn closing_the_connection_ends_it() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    assert_eq!(conn.proxy().list_locations().await.unwrap().len(), 1);
    conn.close().await;
    let e = BridgeError::from(conn.proxy().list_locations().await.unwrap_err());
    assert!(matches!(e, BridgeError::Disconnected(_)), "{e:?}");
}

/// `state` and `stateError` of `loc` in `ListLocations`.
async fn state_of(conn: &netvfs_bridge_proto::Connection, loc: &str) -> (String, Option<String>) {
    let locations = conn.proxy().list_locations().await.unwrap();
    let info = &locations.iter().find(|l| l.id == loc).unwrap().info;
    let text = |key: &str| info.get(key).and_then(|v| netvfs_bridge_proto::value_str(v));
    (text("state").unwrap(), text("stateError"))
}

/// The next `LocationsChanged`, skipping other signals.
async fn locations_changed(signals: &mut SignalStream) {
    while !matches!(next_signal(signals).await, Signal::LocationsChanged) {}
}

#[tokio::test]
async fn connection_states_follow_use_disconnect_and_the_script() {
    let fake = fake_with_account().await;
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    hello(&conn).await;
    let s = |state: &str, error: Option<&str>| (state.to_owned(), error.map(str::to_owned));
    assert_eq!(state_of(&conn, "account:1").await, s("disconnected", None));
    // A call that needs a connection connects it, and tells.
    conn.proxy().capabilities("account:1").await.unwrap();
    locations_changed(&mut signals).await;
    assert_eq!(state_of(&conn, "account:1").await, s("connected", None));
    conn.proxy().disconnect("account:1").await.unwrap();
    locations_changed(&mut signals).await;
    assert_eq!(state_of(&conn, "account:1").await, s("disconnected", None));
    // Scripted: a failure with its error, told once.
    fake.set_state("account:1", "failed", Some("AuthFailed")).await;
    locations_changed(&mut signals).await;
    assert_eq!(state_of(&conn, "account:1").await, s("failed", Some("AuthFailed")));
    fake.set_state("account:1", "failed", Some("AuthFailed")).await;
    conn.proxy().stat("account:1", b"", true, "").await.unwrap();
    locations_changed(&mut signals).await;
    assert_eq!(state_of(&conn, "account:1").await, s("connected", None));
    // Work on a connected location tells nothing more.
    conn.proxy().stat("account:1", b"", true, "").await.unwrap();
    let quiet = tokio::time::timeout(Duration::from_millis(200), signals.next()).await;
    assert!(quiet.is_err(), "{quiet:?}");
    // A connected ad-hoc location.
    let loc = conn.proxy().connect_ad_hoc("sftp://h/", b"", &OptsBuilder::new().build()).await.unwrap();
    assert_eq!(state_of(&conn, &loc).await, s("connected", None));
}

#[tokio::test]
async fn features_and_the_storage_handoff_need_no_consent() {
    // XB-19, XB-15.
    let fake = fake_with_account().await;
    fake.set_consent(netvfs_bridge_proto::fake::Consent::Denied).await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    assert_eq!(conn.proxy().get_features().await.unwrap(), ["storage-settings", "drives"]);
    conn.proxy().open_storage_settings().await.unwrap();
    assert_eq!(fake.handoffs(), ["storage"]);
    // A bridge without the handoff entry.
    fake.set_features(&[]);
    assert!(conn.proxy().get_features().await.unwrap().is_empty());
    let e = BridgeError::from(conn.proxy().open_storage_settings().await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("Unsupported"));
    assert_eq!(fake.handoffs(), ["storage"]);
}

#[tokio::test]
async fn drives_are_listed_mounted_and_unmounted_without_consent() {
    // XB-20.
    use netvfs_bridge_proto::fake::FakeDrive;
    use netvfs_bridge_proto::{drive_info, value_i64, value_str};
    let fake = fake_with_account().await;
    fake.set_consent(netvfs_bridge_proto::fake::Consent::Denied).await;
    let conn = fake.connect().await.unwrap();
    hello(&conn).await;
    let mut signals = conn.signals();
    fake.set_drives(vec![
        FakeDrive::new("mmcblk1p1", "CARD", "sd", 64),
        FakeDrive::new("sda1", "", "usb", 8),
    ])
    .await;
    assert!(changed(&mut signals).await);
    let drives = conn.proxy().list_drives().await.unwrap();
    let ids: Vec<&str> = drives.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, ["mmcblk1p1", "sda1"]);
    assert_eq!(drives[0].label, "CARD");
    assert!(drives[0].mount_point.is_empty());
    assert_eq!(value_str(&drives[0].info[drive_info::KIND]).as_deref(), Some("sd"));
    assert_eq!(value_i64(&drives[0].info[drive_info::SIZE]), Some(64));

    assert_eq!(conn.proxy().mount("mmcblk1p1").await.unwrap(), b"/run/media/user/CARD");
    assert!(changed(&mut signals).await);
    // Mounted already: the same place, no change.
    assert_eq!(conn.proxy().mount("mmcblk1p1").await.unwrap(), b"/run/media/user/CARD");
    assert_eq!(conn.proxy().mount("sda1").await.unwrap(), b"/run/media/user/sda1");
    conn.proxy().unmount("mmcblk1p1").await.unwrap();
    conn.proxy().unmount("mmcblk1p1").await.unwrap();
    assert!(fake.drives()[0].mount_point.is_empty());

    let e = BridgeError::from(conn.proxy().mount("sdb1").await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("NotFound"));
    let e = BridgeError::from(conn.proxy().unmount("../sda1").await.unwrap_err());
    assert!(matches!(e, BridgeError::InvalidArgs(_)), "{e:?}");
}

/// Whether a `DrivesChanged` arrives within a second.
async fn changed(signals: &mut SignalStream) -> bool {
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(signal) = signals.next().await {
            if matches!(signal, Ok(Signal::DrivesChanged)) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}
