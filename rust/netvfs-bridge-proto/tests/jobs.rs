// SPDX-License-Identifier: LGPL-2.1-or-later
//! Jobs and signals of the fake (`Walk`, `CopyAcross`, cancellation, discovery) follow the
//! contract.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "fake")]

use futures_lite::StreamExt as _;
use netvfs_bridge_proto::fake::FakeBridge;
use netvfs_bridge_proto::zvariant::Fd;
use netvfs_bridge_proto::{
    BridgeError, Connection, Opts, OptsBuilder, Signal, SignalStream, WireNearby, value_i64, value_str,
};
use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::time::Duration;

async fn setup() -> (FakeBridge, Connection, SignalStream) {
    let fake = FakeBridge::new();
    fake.add_account(1, "fake", "Fake 1", "fake.example").await;
    fake.add_account(2, "fake", "Fake 2", "other.example").await;
    let conn = fake.connect().await.unwrap();
    let signals = conn.signals();
    conn.proxy().hello("test").await.unwrap();
    (fake, conn, signals)
}

async fn next_signal(signals: &mut SignalStream) -> Signal {
    tokio::time::timeout(Duration::from_secs(5), signals.next())
        .await
        .expect("no signal within five seconds")
        .expect("the stream ended")
        .unwrap()
}

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

async fn levels(conn: &Connection) -> Vec<(String, String)> {
    let locations = conn.proxy().list_locations().await.unwrap();
    locations
        .into_iter()
        .map(|l| (l.id, l.info.get("access").and_then(|v| value_str(v)).expect("an access")))
        .collect()
}

#[tokio::test]
async fn consent_changes_as_in_the_bridge() {
    use netvfs_bridge_proto::access::Level;
    use netvfs_bridge_proto::fake::Consent;
    let fake = FakeBridge::new();
    fake.set_consent(Consent::Unknown).await;
    fake.add_account(1, "fake", "Fake 1", "fake.example").await;
    fake.add_account(2, "fake", "Fake 2", "other.example").await;
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    conn.proxy().hello("test").await.unwrap();
    assert_eq!(conn.proxy().get_consent().await.unwrap(), "unknown");
    assert!(conn.proxy().list_locations().await.unwrap().is_empty());
    fake.set_consent(Consent::Allowed(Level::Read)).await;
    assert!(matches!(next_signal(&mut signals).await, Signal::ConsentChanged(c) if c == "decided"));
    assert!(matches!(next_signal(&mut signals).await, Signal::LocationsChanged));
    let read = |id: &str| (id.to_owned(), "read".to_owned());
    assert_eq!(levels(&conn).await, [read("account:1"), read("account:2")]);
    fake.set_access("account:2", Some(Level::Full)).await;
    assert!(matches!(next_signal(&mut signals).await, Signal::LocationsChanged), "widening keeps clients");
    assert_eq!(levels(&conn).await, [read("account:1"), ("account:2".to_owned(), "full".to_owned())]);
    fake.set_access("account:1", None).await;
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(_)) = signals.next().await {}
    });
    assert!(ended.await.is_ok(), "narrowing disconnects");
    let again = fake.connect().await.unwrap();
    again.proxy().hello("test").await.unwrap();
    assert_eq!(levels(&again).await, [("account:2".to_owned(), "full".to_owned())]);
    let stat = again.proxy().stat("account:1", b"", true, "").await.unwrap_err();
    let detail = match BridgeError::from(stat) {
        BridgeError::Remote { detail, .. } => detail,
        other => panic!("{other:?}"),
    };
    assert_eq!(detail.as_deref(), Some("denied"));
}

#[tokio::test]
async fn failures_can_start_later_and_repeat() {
    use netvfs_bridge_proto::fake::Failure;
    let (fake, conn, _signals) = setup().await;
    fake.fail(Failure::new("GetConsent", "Locked", "busy").after(1).times(2));
    let p = conn.proxy();
    assert_eq!(p.get_consent().await.unwrap(), "decided", "the first call is spared");
    p.get_consent().await.unwrap_err();
    p.get_consent().await.unwrap_err();
    assert_eq!(p.get_consent().await.unwrap(), "decided", "and then it is over");
    fake.fail(Failure::new("*", "Locked", "everything"));
    p.get_consent().await.unwrap_err();
    fake.clear_failures();
    p.get_consent().await.unwrap();
}

async fn put(
    conn: &Connection,
    signals: &mut SignalStream,
    path: &[u8],
    content: &[u8],
    opts: &Opts,
) -> String {
    let file = tempfile_with(content);
    match conn.proxy().upload("account:1", path, Fd::from(file.as_fd()), opts).await {
        Ok(job) => finish(signals, job).await.1,
        Err(e) => BridgeError::from(e).netvfs_name().unwrap_or_default().to_owned(),
    }
}

fn tempfile_with(content: &[u8]) -> std::fs::File {
    let path = std::env::temp_dir().join(format!("fake-put-{}-{}", std::process::id(), rand_suffix()));
    std::fs::write(&path, content).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    file
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher as _, RandomState};
    RandomState::new().hash_one(std::time::SystemTime::now())
}

fn detail<T: std::fmt::Debug>(result: zbus::Result<T>) -> Option<String> {
    match BridgeError::from(result.unwrap_err()) {
        BridgeError::Remote { detail, .. } => detail,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn add_only_keeps_what_the_app_added() {
    use netvfs_bridge_proto::access::Level;
    use netvfs_bridge_proto::fake::{Consent, JobFailure};
    let fake = FakeBridge::new();
    fake.set_consent(Consent::Allowed(Level::Add)).await;
    fake.add_account(1, "fake", "Fake 1", "fake.example").await;
    let conn = fake.connect().await.unwrap();
    let mut signals = conn.signals();
    conn.proxy().hello("test").await.unwrap();
    fake.put_file("account:1", b"in/a.txt", b"hello");
    fake.put_dir("account:1", b"in/sub");
    let p = conn.proxy();
    let add = Some("add".to_owned());
    let req = p.list("account:1", b"in", "", 0).await.unwrap();
    let names = loop {
        if let Signal::ListBatch { req: r, entries } = next_signal(&mut signals).await {
            assert_eq!(r, req);
            break entries.into_iter().map(|e| e.name).collect::<Vec<_>>();
        }
    };
    assert_eq!(names, [b"sub".to_vec()]);
    assert_eq!(detail(p.stat("account:1", b"in/a.txt", true, "").await), add);
    assert_eq!(detail(p.open_read("account:1", b"in/a.txt", "").await), add);
    let create = OptsBuilder::new().build();
    assert_eq!(put(&conn, &mut signals, b"in/.n.part", b"mine", &create).await, "");
    let (handle, size) = p.open_read("account:1", b"in/.n.part", "").await.unwrap();
    assert_eq!(size, 4);
    p.close(handle).await.unwrap();
    p.rename("account:1", b"in/.n.part", b"in/n.txt", false).await.unwrap();
    assert_eq!(detail(p.stat("account:1", b"in/n.txt", true, "").await), add, "renamed: no longer the app's");
    assert_eq!(put(&conn, &mut signals, b"in/a.txt", b"x", &create).await, "AlreadyExists");
    let truncate = OptsBuilder::new().str("disposition", "truncate").build();
    assert_eq!(put(&conn, &mut signals, b"in/a.txt", b"x", &truncate).await, "PermissionDenied");
    assert_eq!(fake.file("account:1", b"in/a.txt").unwrap(), b"hello");
    fake.fail_job(JobFailure::new("Upload", 0, "ConnectionLost", "cut"));
    assert_eq!(put(&conn, &mut signals, b"in/.cut.part", b"abc", &create).await, "ConnectionLost");
    assert_eq!(
        put(&conn, &mut signals, b"in/.cut.part", b"abc", &truncate).await,
        "",
        "a cut upload stays the app's"
    );
    p.remove_file("account:1", b"in/.cut.part").await.unwrap();
    assert!(!fake.exists("account:1", b"in/.cut.part"));
    assert_eq!(detail(p.remove_file("account:1", b"in/a.txt").await), add);
    assert_eq!(
        BridgeError::from(p.remove_file("account:1", b"in/gone").await.unwrap_err()).netvfs_name(),
        Some("NotFound")
    );
    let walk = p.walk("account:1", b"in", &OptsBuilder::new().build()).await.unwrap();
    let (paths, error, _) = finish(&mut signals, walk).await;
    assert_eq!((paths, error.as_str()), (vec![b"in/sub".to_vec()], ""));
}
