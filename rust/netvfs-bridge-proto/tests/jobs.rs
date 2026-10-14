// SPDX-License-Identifier: LGPL-2.1-or-later
//! Jobs and signals of the fake (`Walk`, `CopyAcross`, cancellation,
//! discovery) follow the contract (SPEC-v2 XB-10, XB-11).
// Test helpers outside #[test] functions: a failing test is the point.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "fake")]

use futures_lite::StreamExt as _;
use netvfs_bridge_proto::fake::FakeBridge;
use netvfs_bridge_proto::{
    BridgeError, Connection, OptsBuilder, PROTOCOL_VERSION, Signal, SignalStream, WireNearby, value_i64,
};
use std::collections::HashMap;
use std::time::Duration;

async fn setup() -> (FakeBridge, Connection, SignalStream) {
    let fake = FakeBridge::new();
    fake.add_account(1, "fake", "Fake 1", "fake.example").await;
    fake.add_account(2, "fake", "Fake 2", "other.example").await;
    let conn = fake.connect().await.unwrap();
    let signals = conn.signals();
    conn.proxy().hello(PROTOCOL_VERSION, "test").await.unwrap();
    (fake, conn, signals)
}

/// The next signal; fails after five seconds instead of waiting forever.
async fn next_signal(signals: &mut SignalStream) -> Signal {
    tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("no signal within five seconds")
        .expect("the stream ended")
        .unwrap()
}

/// Reads signals until the job finishes; returns the walked paths and the extras.
async fn finish(signals: &mut SignalStream, job: u32) -> (Vec<Vec<u8>>, String, HashMap<String, i64>) {
    let mut paths = Vec::new();
    loop {
        let signal = tokio::time::timeout(Duration::from_secs(5), signals.next())
            .await
            .expect("the job never finished")
            .expect("the stream ended")
            .unwrap();
        match signal {
            Signal::WalkBatch { job: j, entries } => {
                assert_eq!(j, job);
                paths.extend(entries.into_iter().map(|e| e.path));
            }
            Signal::JobFinished { job: j, error, extra, .. } => {
                assert_eq!(j, job);
                let ints = extra.iter().filter_map(|(k, v)| value_i64(v).map(|n| (k.clone(), n))).collect();
                return (paths, error, ints);
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn walk_streams_the_tree_depth_first() {
    let (fake, conn, mut signals) = setup().await;
    for path in ["t/a", "t/sub/b", "t/sub/deep/c", "t/z"] {
        fake.put_file("account:1", path.as_bytes(), b"x");
    }
    let job = conn.proxy().walk("account:1", b"t", &OptsBuilder::new().build()).await.unwrap();
    let (paths, error, extra) = finish(&mut signals, job).await;
    assert_eq!(error, "");
    let want: Vec<&[u8]> = vec![b"t/a", b"t/sub", b"t/sub/b", b"t/sub/deep", b"t/sub/deep/c", b"t/z"];
    assert_eq!(paths, want);
    assert_eq!(extra["entries"], 6);

    let shallow = OptsBuilder::new().int("maxDepth", 1).build();
    let job = conn.proxy().walk("account:1", b"t", &shallow).await.unwrap();
    let (paths, _, _) = finish(&mut signals, job).await;
    assert_eq!(paths.len(), 3);

    let post = OptsBuilder::new().bool("postOrder", true).build();
    let job = conn.proxy().walk("account:1", b"t", &post).await.unwrap();
    let (paths, _, _) = finish(&mut signals, job).await;
    assert_eq!(paths.first().map(Vec::as_slice), Some(&b"t/z"[..]), "children come before their folder");

    let job = conn.proxy().walk("account:1", b"missing", &OptsBuilder::new().build()).await.unwrap();
    let (_, error, _) = finish(&mut signals, job).await;
    assert_eq!(error, "NotFound");
}

#[tokio::test]
async fn copy_across_moves_a_tree_between_locations() {
    let (fake, conn, mut signals) = setup().await;
    fake.put_file("account:1", b"src/a", b"1234");
    fake.put_file("account:1", b"src/sub/b", b"56");
    fake.put_dir("account:2", b"dst");
    let recursive = OptsBuilder::new().bool("recursive", true).build();
    let job =
        conn.proxy().copy_across("account:1", b"src", "account:2", b"dst/copy", &recursive).await.unwrap();
    let (_, error, extra) = finish(&mut signals, job).await;
    assert_eq!(error, "");
    assert_eq!(extra["bytes"], 6);
    assert_eq!(fake.file("account:2", b"dst/copy/sub/b").unwrap(), b"56");

    // The destination exists now: refused without `replace`, allowed with it.
    let job =
        conn.proxy().copy_across("account:1", b"src", "account:2", b"dst/copy", &recursive).await.unwrap();
    assert_eq!(finish(&mut signals, job).await.1, "AlreadyExists");
    let replace = OptsBuilder::new().bool("recursive", true).bool("replace", true).build();
    let job =
        conn.proxy().copy_across("account:1", b"src", "account:2", b"dst/copy", &replace).await.unwrap();
    assert_eq!(finish(&mut signals, job).await.1, "");

    let e = BridgeError::from(
        conn.proxy().copy_across("account:1", b"src", "account:9", b"x", &recursive).await.unwrap_err(),
    );
    assert_eq!(e.netvfs_name(), Some("NotFound"));
}

#[tokio::test]
async fn server_copy_needs_the_recursive_option_for_folders() {
    let (fake, conn, _signals) = setup().await;
    fake.put_file("account:1", b"d/f", b"x");
    let p = conn.proxy();
    let plain = OptsBuilder::new().build();
    let e = BridgeError::from(p.server_copy("account:1", b"d", b"copy", &plain).await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("IsADirectory"));
    p.server_copy("account:1", b"d", b"copy", &OptsBuilder::new().bool("recursive", true).build())
        .await
        .unwrap();
    assert_eq!(fake.file("account:1", b"copy/f").unwrap(), b"x");
}

#[tokio::test]
async fn a_listing_can_be_canceled() {
    let (fake, conn, mut signals) = setup().await;
    for i in 0..20 {
        fake.put_file("account:1", format!("d/f{i}").as_bytes(), b"x");
    }
    fake.set_latency(Duration::from_millis(30));
    let req = conn.proxy().list("account:1", b"d", "", 1).await.unwrap();
    conn.proxy().cancel(req).await.unwrap();
    let mut batches = 0;
    loop {
        match next_signal(&mut signals).await {
            Signal::ListBatch { .. } => batches += 1,
            Signal::ListDone { error, .. } => {
                assert_eq!(error, "Canceled");
                break;
            }
            _ => {}
        }
    }
    assert!(batches < 20, "stopped early after {batches} batches");
    // A finished request can still be canceled quietly; an unknown id is refused.
    conn.proxy().cancel(req).await.unwrap();
    let e = BridgeError::from(conn.proxy().cancel(999).await.unwrap_err());
    assert_eq!(e.netvfs_name(), Some("NotFound"));
}

#[tokio::test]
async fn discovery_results_arrive_as_signals() {
    let (fake, conn, mut signals) = setup().await;
    let server = WireNearby { name: "NAS".into(), provider: "smb".into(), host: "nas".into(), port: 445 };
    fake.set_nearby(vec![server.clone()]).await;
    conn.proxy().discover(true).await.unwrap();
    loop {
        if let Signal::NearbyChanged(list) = next_signal(&mut signals).await {
            assert_eq!(list, vec![server]);
            break;
        }
    }
}

#[tokio::test]
async fn consent_and_location_changes_are_signalled() {
    let (fake, _conn, mut signals) = setup().await;
    fake.set_consent(netvfs_bridge_proto::fake::Consent::Denied).await;
    fake.add_account(3, "fake", "Fake 3", "third.example").await;
    let mut seen = (false, false);
    while seen != (true, true) {
        match next_signal(&mut signals).await {
            Signal::ConsentChanged(c) => {
                assert_eq!(c, "denied");
                seen.0 = true;
            }
            Signal::LocationsChanged => seen.1 = true,
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn failures_can_start_later_and_repeat() {
    use netvfs_bridge_proto::fake::Failure;
    let (fake, conn, _signals) = setup().await;
    fake.fail(Failure::new("GetConsent", "Locked", "busy").after(1).times(2));
    let p = conn.proxy();
    assert_eq!(p.get_consent().await.unwrap(), "granted", "the first call is spared");
    p.get_consent().await.unwrap_err();
    p.get_consent().await.unwrap_err();
    assert_eq!(p.get_consent().await.unwrap(), "granted", "and then it is over");
    fake.fail(Failure::new("*", "Locked", "everything"));
    p.get_consent().await.unwrap_err();
    fake.clear_failures();
    p.get_consent().await.unwrap();
}
