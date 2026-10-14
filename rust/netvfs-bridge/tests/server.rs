// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bridge end to end (design §4.1, chunk E): the core with the socket
//! front, in-process ([`Fixture`]), against the real
//! `libnetvfs-bridge-ffi.so` and the fake backend, through the protocol
//! crate's client. The Rust side of netvfs 0.4's C++ `tst_bridgeserver`.
//! Without the C ABI (the variables of [`testing::VARIABLES`]) every test
//! says it is skipped and passes.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::assertions_on_result_states
)]

use netvfs_bridge::accounts::{Attention, Value};
use netvfs_bridge::consent::Consent;
use netvfs_bridge::core::nearby::{self, NearbySource as _};
use netvfs_bridge::handoff::HandoffArg;
use netvfs_bridge::locations::knownhosts::KnownHosts;
use netvfs_bridge::server::ListenAddress;
use netvfs_bridge::testing::{
    self, ACCOUNT_LOC, FakeAccounts, Fixture, Harness, Setup, Test, WAIT, block_on, error_name,
    wait_disconnected, wait_for, wait_signal,
};
use netvfs_bridge::testutil::TempDir;
use netvfs_bridge::{Deps, Services};
use netvfs_bridge_proto::limits::{MAX_HANDLES, MAX_JOBS, MAX_LIST_BATCH, MAX_REQUESTS, POOL_PER_HOST};
use netvfs_bridge_proto::zvariant::Fd;
use netvfs_bridge_proto::{Connection, ErrorName, Opts, OptsBuilder, PROTOCOL_VERSION, Signal, SignalStream};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsFd as _;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, Instant};

const TESTS: &[(&str, Test)] = &[
    ("hello_first", hello_first),
    ("hello_and_locations", hello_and_locations),
    ("consent_unknown_then_granted", consent_unknown_then_granted),
    ("consent_denied", consent_denied),
    ("revocation_mid_job", revocation_mid_job),
    ("list_streams_batches", list_streams_batches),
    ("zbus_send_ordering", zbus_send_ordering),
    ("cancel_job", cancel_job),
    ("disconnect_cancels_jobs", disconnect_cancels_jobs),
    ("idle_exit", idle_exit),
    ("metadata_and_namespace", metadata_and_namespace),
    ("path_validation", path_validation),
    ("handles", handles),
    ("handle_limit", handle_limit),
    ("request_limit", request_limit),
    ("job_limit", job_limit),
    ("upload_and_download_regular", upload_and_download_regular),
    ("transfer_through_pipes", transfer_through_pipes),
    ("fd_validation", fd_validation),
    ("walk_remove_tree_copy_across", walk_remove_tree_copy_across),
    ("walk_batch_limit", walk_batch_limit),
    ("account_identity_changed_sets_attention", account_identity_changed_sets_attention),
    ("ad_hoc_identity_question", ad_hoc_identity_question),
    ("keyboard_interactive", keyboard_interactive),
    ("connect_ad_hoc_refusals", connect_ad_hoc_refusals),
    ("peer_check_refuses", peer_check_refuses),
    ("discovery", discovery),
    ("handoff", handoff),
    ("locations_changed", locations_changed),
    ("ffi_nearby_lives_on_the_qt_thread", ffi_nearby_lives_on_the_qt_thread),
    ("cancel_copy_across", cancel_copy_across),
    ("cancel_pending_job", cancel_pending_job),
    ("idle_exit_after_an_answer", idle_exit_after_an_answer),
    ("debug_output", debug_output),
];

fn main() -> ExitCode {
    testing::run_main("netvfs-bridge-server-test", TESTS)
}

/// What [`error_name`] gives for a failure with `e`.
#[allow(clippy::unnecessary_wraps, reason = "compared with error_name")]
fn name(e: ErrorName) -> Option<String> {
    Some(e.dbus_name().to_owned())
}

fn no_opts() -> Opts {
    Opts::new()
}

// ---------------------------------------------------------------- tests

fn hello_first(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.client().await;
        let early = c.proxy().get_consent().await;
        assert_eq!(error_name(&early), name(ErrorName::ProtocolError));
        let (protocol, version, features) = c.proxy().hello(PROTOCOL_VERSION, "t").await.unwrap();
        assert_eq!(protocol, PROTOCOL_VERSION);
        assert!(!version.is_empty());
        assert!(!features.is_empty());
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        // A second Hello is answered as well.
        assert!(c.proxy().hello(PROTOCOL_VERSION, "t").await.is_ok());
        assert_eq!(f.prompt.state().shown, 0);
    });
}

fn hello_and_locations(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let locations = c.proxy().list_locations().await.unwrap();
        assert_eq!(locations.len(), 1);
        let l = &locations[0];
        assert_eq!((l.id.as_str(), l.provider.as_str(), l.name.as_str()), (ACCOUNT_LOC, "fake", "Fake 1"));
        let caps = c.proxy().capabilities(ACCOUNT_LOC).await.unwrap();
        assert!(caps.flags.iter().any(|f| f == "ReadHandles"), "{caps:?}");
        assert_eq!(error_name(&c.proxy().capabilities("account:9").await), name(ErrorName::NotFound));
        assert_eq!(f.prompt.state().shown, 0);
        let counters = f.probe().counters().await.unwrap();
        assert_eq!((counters.sessions, counters.requests, counters.pools), (1, 0, 1));
    });
}

fn consent_unknown_then_granted(h: &Harness) {
    let f = Fixture::new(h, Consent::Unknown);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        assert_eq!(f.prompt.state().shown, 1); // XB-6: first Hello while unknown
        assert_eq!(f.prompt.state().display_name, "Test");
        assert_eq!(c.proxy().get_consent().await.unwrap(), "unknown");
        assert!(c.proxy().list_locations().await.unwrap().is_empty());
        let stat = c.proxy().stat(ACCOUNT_LOC, b"/x", true, "").await;
        assert_eq!(error_name(&stat), name(ErrorName::PermissionDenied));
        assert_eq!(error_name(&c.proxy().discover(true).await), name(ErrorName::PermissionDenied));
        c.proxy().hello(PROTOCOL_VERSION, "t").await.unwrap();
        assert_eq!(f.prompt.state().shown, 1); // not again while shown
        f.answer_prompt(true);
        let changed = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::ConsentChanged(_))).await;
        assert!(matches!(changed, Some(Signal::ConsentChanged(ref v)) if v == "granted"), "{changed:?}");
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        assert_eq!(f.stored_consent(), Consent::Granted);
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 1);
        assert_eq!(f.prompt.state().withdrawn, 1);
    });
}

fn consent_denied(h: &Harness) {
    let f = Fixture::new(h, Consent::Denied);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        assert_eq!(f.prompt.state().shown, 0);
        assert_eq!(c.proxy().get_consent().await.unwrap(), "denied");
        assert!(c.proxy().list_locations().await.unwrap().is_empty());
        let list = c.proxy().list(ACCOUNT_LOC, b"", "", 0).await;
        assert_eq!(error_name(&list), name(ErrorName::PermissionDenied));
        c.proxy().request_consent().await.unwrap();
        assert_eq!(f.prompt.state().shown, 1);
        f.answer_prompt(false);
        let changed =
            wait_signal(&mut signals, Duration::from_millis(300), |s| matches!(s, Signal::ConsentChanged(_)))
                .await;
        assert!(changed.is_none(), "denied stays denied: {changed:?}");
        assert_eq!(f.stored_consent(), Consent::Denied);
        assert_eq!(c.proxy().get_consent().await.unwrap(), "denied");
    });
}

/// A download of 4 MiB at 50 ms a chunk into a pipe nobody reads.
async fn slow_download(f: &Fixture, c: &Connection) -> (u32, std::io::PipeReader) {
    f.harness.fake.add_file(b"/big", &vec![b'x'; 4 << 20]);
    f.harness.fake.set_chunk_delay_ms(50);
    let (reader, writer) = std::io::pipe().unwrap();
    let job = c.proxy().download(ACCOUNT_LOC, b"/big", Fd::from(writer.as_fd()), &no_opts()).await.unwrap();
    drop(writer);
    (job, reader)
}

fn revocation_mid_job(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let (_job, reader) = slow_download(&f, &c).await;
        let probe = f.probe();
        assert_eq!(probe.wait_until(WAIT, |n| n.jobs == 1).await.unwrap().jobs, 1);
        // netvfs-ui revokes: bridge.conf changes on disk.
        let started = Instant::now();
        f.set_consent(Consent::Denied);
        assert!(wait_disconnected(&mut signals, Duration::from_secs(3)).await);
        let after =
            probe.wait_until(Duration::from_secs(3), |n| n.jobs == 0 && n.sessions == 0).await.unwrap();
        assert_eq!((after.jobs, after.sessions, after.pools), (0, 0, 0));
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        drop(reader);
        // A new client is still refused location calls.
        let again = f.hello_client().await;
        assert!(again.proxy().list_locations().await.unwrap().is_empty());
        assert_eq!(again.proxy().get_consent().await.unwrap(), "denied");
    });
}

fn list_streams_batches(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    for i in 0..1000 {
        f.harness.fake.add_file(format!("/many/f{i:04}").as_bytes(), b"x");
    }
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let request = c.proxy().list(ACCOUNT_LOC, b"/many", "bulk", 100).await.unwrap();
        let (mut total, mut batches) = (0, 0);
        loop {
            let s = wait_signal(&mut signals, WAIT, |s| {
                matches!(s, Signal::ListBatch { .. } | Signal::ListDone { .. })
            })
            .await
            .expect("ListDone");
            match s {
                Signal::ListBatch { req, entries } => {
                    assert_eq!(req, request);
                    assert!(!entries.is_empty() && entries.len() <= 100, "{}", entries.len());
                    total += entries.len();
                    batches += 1;
                }
                Signal::ListDone { req, error, .. } => {
                    assert_eq!((req, error.as_str()), (request, ""));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(total, 1000);
        assert!(batches >= 10, "{batches}");
        // A missing folder: ListDone carries the error name.
        let missing = c.proxy().list(ACCOUNT_LOC, b"/nope", "", 0).await.unwrap();
        assert!(missing > request);
        let done = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::ListDone { .. })).await;
        assert!(
            matches!(done, Some(Signal::ListDone { req, ref error, .. }) if req == missing && error == "NotFound")
        );
        let counters = f.probe().counters().await.unwrap();
        assert_eq!((counters.requests, counters.ops), (0, 0));
    });
}

/// What one `List` brought, in arrival order.
#[derive(Debug, PartialEq, Eq)]
enum Arrived {
    Reply(u32),
    Batch(u32),
    Done(u32),
}

/// The next message on `stream` that belongs to the `List` call `serial`
/// or to a listing: its reply, a `ListBatch`, a `ListDone`.
async fn next_arrival(stream: &mut zbus::MessageStream, serial: std::num::NonZeroU32) -> Arrived {
    use futures_lite::StreamExt as _;
    loop {
        let message = tokio::time::timeout(WAIT, stream.next()).await.expect("a message").unwrap().unwrap();
        let header = message.header();
        match message.message_type() {
            zbus::message::Type::MethodReturn if header.reply_serial() == Some(serial) => {
                return Arrived::Reply(message.body().deserialize().unwrap());
            }
            zbus::message::Type::Error if header.reply_serial() == Some(serial) => {
                panic!("List failed: {message:?}");
            }
            zbus::message::Type::Signal => match header.member().map(zbus::names::MemberName::as_str) {
                Some("ListBatch") => {
                    let (req, _): (u32, Vec<netvfs_bridge_proto::WireEntry>) =
                        message.body().deserialize().unwrap();
                    return Arrived::Batch(req);
                }
                Some("ListDone") => {
                    let (req, _, _): (u32, String, String) = message.body().deserialize().unwrap();
                    return Arrived::Done(req);
                }
                _ => {}
            },
            _ => {}
        }
    }
}

// Design §3.4, §4.2: one writer per session keeps the reply to List ahead
// of its ListBatch signals and those ahead of ListDone, every time.
fn zbus_send_ordering(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    for i in 0..3 {
        h.fake.add_file(format!("/o/f{i}").as_bytes(), b"x");
    }
    block_on(async {
        let c = f.hello_client().await;
        let z = c.zbus();
        let mut stream = zbus::MessageStream::from(z);
        for round in 0..1000 {
            let call = zbus::Message::method_call(netvfs_bridge_proto::OBJECT_PATH, "List")
                .unwrap()
                .interface(netvfs_bridge_proto::INTERFACE)
                .unwrap()
                .build(&(ACCOUNT_LOC, b"/o".to_vec(), "", 1_u32))
                .unwrap();
            let serial = call.primary_header().serial_num();
            z.send(&call).await.unwrap();
            let Arrived::Reply(req) = next_arrival(&mut stream, serial).await else {
                panic!("round {round}: a signal before the reply");
            };
            let mut got = Vec::new();
            loop {
                let arrived = next_arrival(&mut stream, serial).await;
                let done = arrived == Arrived::Done(req);
                got.push(arrived);
                if done {
                    break;
                }
            }
            let want = [Arrived::Batch(req), Arrived::Batch(req), Arrived::Batch(req), Arrived::Done(req)];
            assert_eq!(got, want, "round {round}");
        }
    });
}

fn cancel_job(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let (job, _reader) = slow_download(&f, &c).await;
        assert_eq!(error_name(&c.proxy().cancel(0).await), name(ErrorName::NotFound));
        assert_eq!(error_name(&c.proxy().cancel(job + 1).await), name(ErrorName::NotFound));
        c.proxy().cancel(job).await.unwrap();
        let finished = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::JobFinished { .. })).await;
        match finished {
            Some(Signal::JobFinished { job: id, error, .. }) => {
                assert_eq!((id, error.as_str()), (job, "Canceled"));
            }
            other => panic!("{other:?}"),
        }
        // An id that already finished: nothing to do.
        c.proxy().cancel(job).await.unwrap();
        let counters = f.probe().wait_until(WAIT, |n| n.jobs == 0 && n.ops == 0).await.unwrap();
        assert_eq!((counters.jobs, counters.ops), (0, 0));
    });
}

fn disconnect_cancels_jobs(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let (_job, _reader) = slow_download(&f, &c).await;
        let probe = f.probe();
        assert_eq!(probe.wait_until(WAIT, |n| n.jobs == 1).await.unwrap().jobs, 1);
        c.close().await;
        drop(c);
        let after =
            probe.wait_until(Duration::from_secs(3), |n| n.jobs == 0 && n.sessions == 0).await.unwrap();
        assert_eq!((after.jobs, after.sessions, after.requests), (0, 0, 0));
    });
}

fn idle_exit(h: &Harness) {
    let mut f = Fixture::with_idle_exit(h, Consent::Granted, Duration::from_millis(300));
    block_on(async {
        let c = f.hello_client().await;
        // Not while a consumer is connected.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(f.probe().counters().await.is_some());
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        c.close().await;
        drop(c);
        let started = Instant::now();
        assert_eq!(f.wait_exit(Duration::from_secs(5)).await, Some(ExitCode::SUCCESS));
        assert!(started.elapsed() >= Duration::from_millis(250), "{:?}", started.elapsed());
        assert!(f.probe().counters().await.is_none());
        assert!(netvfs_bridge_proto::connect(&f.socket).await.is_err());
    });
}

/// The next `JobFinished` of `job`: its error name, message and extra.
async fn finished(
    signals: &mut SignalStream,
    job: u32,
) -> (String, String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) {
    match wait_signal(signals, WAIT, |s| matches!(s, Signal::JobFinished { job: j, .. } if *j == job)).await {
        Some(Signal::JobFinished { error, message, extra, .. }) => (error, message, extra),
        other => panic!("{other:?}"),
    }
}

fn count(extra: &std::collections::HashMap<String, zbus::zvariant::OwnedValue>, key: &str) -> i64 {
    i64::try_from(&extra[key]).unwrap()
}

fn metadata_and_namespace(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    let fake = h.fake;
    fake.add_file(b"/docs/a.txt", b"hello");
    block_on(async {
        let c = f.hello_client().await;
        let p = c.proxy();
        let entry = p.stat(ACCOUNT_LOC, b"/docs/a.txt", true, "").await.unwrap();
        assert_eq!((entry.name.as_slice(), entry.size), (&b"a.txt"[..], 5));
        assert_eq!(error_name(&p.stat(ACCOUNT_LOC, b"/docs/zz", true, "").await), name(ErrorName::NotFound));
        p.make_dir(ACCOUNT_LOC, b"/docs/new", true).await.unwrap();
        assert!(fake.exists(b"/docs/new"));
        assert_eq!(
            error_name(&p.make_dir(ACCOUNT_LOC, b"/docs/new", true).await),
            name(ErrorName::AlreadyExists)
        );
        p.make_dir(ACCOUNT_LOC, b"/docs/new", false).await.unwrap();
        fake.add_file(b"/docs/b.txt", b"b");
        let no_replace = p.rename(ACCOUNT_LOC, b"/docs/a.txt", b"/docs/b.txt", false).await;
        assert_eq!(error_name(&no_replace), name(ErrorName::AlreadyExists));
        p.rename(ACCOUNT_LOC, b"/docs/a.txt", b"/docs/b.txt", true).await.unwrap();
        assert_eq!(fake.file_data(b"/docs/b.txt").as_deref(), Some(&b"hello"[..]));
        p.remove_file(ACCOUNT_LOC, b"/docs/b.txt").await.unwrap();
        assert!(!fake.exists(b"/docs/b.txt"));
        p.remove_dir(ACCOUNT_LOC, b"/docs/new").await.unwrap();
        assert!(!fake.exists(b"/docs/new"));
        p.set_attributes(ACCOUNT_LOC, b"/docs", &OptsBuilder::new().int("mode", 0o700).build())
            .await
            .unwrap();
        assert_eq!(fake.node_mode(b"/docs"), Some(0o700));
        // Nothing to change: no round trip, also for a missing file.
        let calls = fake.log_count("");
        p.set_attributes(ACCOUNT_LOC, b"/docs/none", &no_opts()).await.unwrap();
        assert_eq!(fake.log_count(""), calls);
        p.make_symlink(ACCOUNT_LOC, b"../t", b"/docs/l").await.unwrap();
        assert_eq!(p.read_link(ACCOUNT_LOC, b"/docs/l").await.unwrap(), b"../t");
        let (free, total, used) = p.space_info(ACCOUNT_LOC, b"/").await.unwrap();
        assert_eq!((free, total), (1 << 40, 1 << 41));
        assert!(used >= -1);
        fake.add_file(b"/docs/c", b"abc");
        p.server_copy(ACCOUNT_LOC, b"/docs/c", b"/docs/d", &no_opts()).await.unwrap();
        assert_eq!(fake.file_data(b"/docs/d").as_deref(), Some(&b"abc"[..]));
        let replace = OptsBuilder::new().bool("replace", false).build();
        assert_eq!(
            error_name(&p.server_copy(ACCOUNT_LOC, b"/docs/c", b"/docs/d", &replace).await),
            name(ErrorName::AlreadyExists)
        );
        p.make_hardlink(ACCOUNT_LOC, b"/docs/c", b"/docs/h").await.unwrap();
        assert_eq!(fake.file_data(b"/docs/h").as_deref(), Some(&b"abc"[..]));
        assert_eq!(p.checksum(ACCOUNT_LOC, b"/docs/c", "sha256").await.unwrap().len(), 32);
        assert_eq!(error_name(&p.stat("account:99", b"/", true, "").await), name(ErrorName::NotFound));
        let counters = f.probe().counters().await.unwrap();
        assert_eq!(counters.requests, 0);
    });
}

fn path_validation(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let p = c.proxy();
        assert_eq!(error_name(&p.stat(ACCOUNT_LOC, b"a/../b", true, "").await), name(ErrorName::InvalidName));
        assert_eq!(error_name(&p.remove_file(ACCOUNT_LOC, b"a\0b").await), name(ErrorName::InvalidName));
        assert_eq!(h.fake.log_count("remove"), 0); // nothing reached the backend
        assert_eq!(h.fake.log_count("connect"), 0);
    });
}

fn handles(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.add_file(b"/v.bin", b"0123456789");
    block_on(async {
        let c = f.hello_client().await;
        let p = c.proxy();
        let probe = f.probe();
        let (handle, size) = p.open_read(ACCOUNT_LOC, b"/v.bin", "stream").await.unwrap();
        assert_eq!(size, 10);
        assert_eq!(probe.counters().await.unwrap().handles, 1);
        assert_eq!(p.read(handle, 3, 4).await.unwrap(), b"3456");
        p.read_ahead(handle, 0, 100).await.unwrap();
        assert_eq!(p.read(handle, 8, 1 << 20).await.unwrap(), b"89");
        assert_eq!(p.read(handle, 10, 5).await.unwrap(), b"");
        assert_eq!(
            error_name(&p.read(handle, 0, (1 << 20) + 1).await).as_deref(),
            Some("org.freedesktop.DBus.Error.InvalidArgs")
        );
        let (second, _) = p.open_read(ACCOUNT_LOC, b"/v.bin", "").await.unwrap();
        assert_ne!(second, handle);
        p.close(handle).await.unwrap();
        assert_eq!(probe.counters().await.unwrap().handles, 1);
        assert_eq!(error_name(&p.read(handle, 0, 1).await), name(ErrorName::NotFound));
        assert_eq!(error_name(&p.read_ahead(handle, 0, 1).await), name(ErrorName::NotFound));
        assert_eq!(error_name(&p.close(handle).await), name(ErrorName::NotFound));
        assert_eq!(error_name(&p.open_read(ACCOUNT_LOC, b"/none", "").await), name(ErrorName::NotFound));
        assert_eq!(probe.counters().await.unwrap().handles, 1);
        // Disconnect drops the location's connections: the handle is gone.
        p.disconnect(ACCOUNT_LOC).await.unwrap();
        assert_eq!(error_name(&p.read(second, 0, 1).await), name(ErrorName::ConnectionLost));
        assert_eq!(error_name(&p.read_ahead(second, 0, 1).await), name(ErrorName::ConnectionLost));
        p.close(second).await.unwrap();
        assert_eq!(probe.counters().await.unwrap().handles, 0);
        assert_eq!(error_name(&p.disconnect("account:9").await), name(ErrorName::NotFound));
    });
}

fn handle_limit(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.add_file(b"/v.bin", b"x");
    block_on(async {
        let c = f.hello_client().await;
        for _ in 0..MAX_HANDLES {
            c.proxy().open_read(ACCOUNT_LOC, b"/v.bin", "").await.unwrap();
        }
        let over = c.proxy().open_read(ACCOUNT_LOC, b"/v.bin", "").await;
        assert_eq!(error_name(&over), name(ErrorName::TooManyConnections));
        let probe = f.probe();
        assert_eq!(probe.counters().await.unwrap().handles, MAX_HANDLES);
        // A failing open gives its slot back.
        let c2 = f.hello_client().await;
        c.close().await;
        drop(c);
        let after = probe.wait_until(WAIT, |n| n.handles == 0).await.unwrap();
        assert_eq!((after.handles, after.requests), (0, 0));
        assert_eq!(
            error_name(&c2.proxy().open_read(ACCOUNT_LOC, b"/none", "").await),
            name(ErrorName::NotFound)
        );
        assert_eq!(probe.counters().await.unwrap().handles, 0);
    });
}

fn request_limit(h: &Harness) {
    let f = Fixture::start(h, Setup { hang_accounts: true, ..Setup::default() });
    block_on(async {
        let c = f.hello_client().await;
        let mut pending = Vec::new();
        for _ in 0..MAX_REQUESTS {
            let proxy = c.proxy().clone();
            pending.push(tokio::spawn(async move { proxy.stat(ACCOUNT_LOC, b"/x", true, "").await }));
        }
        let probe = f.probe();
        assert_eq!(
            probe.wait_until(WAIT, |n| n.requests == MAX_REQUESTS).await.unwrap().requests,
            MAX_REQUESTS
        );
        let over = c.proxy().stat(ACCOUNT_LOC, b"/x", true, "").await;
        assert_eq!(error_name(&over), name(ErrorName::TooManyConnections));
        let over = netvfs_bridge_proto::BridgeError::from(over.unwrap_err());
        assert!(format!("{over:?}").contains("1000"), "{over:?}");
        // Session-level calls are not limited by pending location work.
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        // Disconnecting cancels the waits (XB-13).
        c.close().await;
        drop(c);
        let after = probe.wait_until(Duration::from_secs(5), |n| n.requests == 0).await.unwrap();
        assert_eq!(after.requests, 0);
        for p in pending {
            assert!(p.await.unwrap().is_err());
        }
    });
}

fn job_limit(h: &Harness) {
    let f = Fixture::start(h, Setup { hang_accounts: true, ..Setup::default() });
    block_on(async {
        let c = f.hello_client().await;
        let mut jobs = Vec::new();
        for _ in 0..MAX_JOBS {
            jobs.push(c.proxy().remove_tree(ACCOUNT_LOC, b"/x").await.unwrap());
        }
        jobs.dedup();
        assert_eq!(jobs.len(), MAX_JOBS);
        let probe = f.probe();
        assert_eq!(probe.counters().await.unwrap().jobs, MAX_JOBS);
        assert_eq!(
            error_name(&c.proxy().remove_tree(ACCOUNT_LOC, b"/x").await),
            name(ErrorName::TooManyConnections)
        );
        let (reader, writer) = std::io::pipe().unwrap();
        assert_eq!(
            error_name(&c.proxy().download(ACCOUNT_LOC, b"/x", Fd::from(writer.as_fd()), &no_opts()).await),
            name(ErrorName::TooManyConnections)
        );
        drop((reader, writer));
        let mut signals = c.signals();
        c.proxy().cancel(jobs[0]).await.unwrap();
        let (error, _, _) = finished(&mut signals, jobs[0]).await;
        assert_eq!(error, "Canceled");
        assert_eq!(probe.wait_until(WAIT, |n| n.jobs == MAX_JOBS - 1).await.unwrap().jobs, MAX_JOBS - 1);
        c.close().await;
        drop(c);
        assert_eq!(probe.wait_until(Duration::from_secs(5), |n| n.jobs == 0).await.unwrap().jobs, 0);
    });
}

fn temp_file(dir: &TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
    dir.write(name, data)
}

fn upload_and_download_regular(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    let dir = TempDir::new();
    let local = temp_file(&dir, "up.bin", b"0123456789");
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let mut rd = File::open(&local).unwrap();
        rd.seek(SeekFrom::Start(7)).unwrap();
        let opts = OptsBuilder::new().int("offset", 2).int("size", 5).build();
        let job = c.proxy().upload(ACCOUNT_LOC, b"/up.bin", Fd::from(rd.as_fd()), &opts).await.unwrap();
        let (error, message, extra) = finished(&mut signals, job).await;
        assert_eq!(error, "", "{message}");
        assert_eq!(count(&extra, "bytes"), 5);
        assert_eq!(h.fake.file_data(b"/up.bin").as_deref(), Some(&b"23456"[..]));
        assert_eq!(rd.stream_position().unwrap(), 7); // pread: the consumer's offset is untouched
        // CreateNew is the default: a second upload to the same name fails.
        let rd2 = File::open(&local).unwrap();
        let job = c.proxy().upload(ACCOUNT_LOC, b"/up.bin", Fd::from(rd2.as_fd()), &no_opts()).await.unwrap();
        assert_eq!(finished(&mut signals, job).await.0, "AlreadyExists");

        h.fake.add_file(b"/down.bin", b"abcdefgh");
        let target = temp_file(&dir, "down.bin", b"........");
        let wr = OpenOptions::new().write(true).open(&target).unwrap();
        let opts = OptsBuilder::new().int("offset", 3).build();
        let job = c.proxy().download(ACCOUNT_LOC, b"/down.bin", Fd::from(wr.as_fd()), &opts).await.unwrap();
        drop(wr);
        let (error, message, extra) = finished(&mut signals, job).await;
        assert_eq!(error, "", "{message}");
        assert_eq!(count(&extra, "bytes"), 5);
        assert_eq!(std::fs::read(&target).unwrap(), b"...defgh");
        // A missing remote file.
        let wr = OpenOptions::new().write(true).open(&target).unwrap();
        let job = c.proxy().download(ACCOUNT_LOC, b"/none", Fd::from(wr.as_fd()), &no_opts()).await.unwrap();
        assert_eq!(finished(&mut signals, job).await.0, "NotFound");
        assert_eq!(f.probe().wait_until(WAIT, |n| n.jobs == 0).await.unwrap().jobs, 0);
    });
}

fn transfer_through_pipes(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let (up_reader, mut up_writer) = std::io::pipe().unwrap();
        up_writer.write_all(b"streamed").unwrap();
        drop(up_writer);
        let job = c
            .proxy()
            .upload(ACCOUNT_LOC, b"/fifo.bin", Fd::from(up_reader.as_fd()), &no_opts())
            .await
            .unwrap();
        drop(up_reader);
        let (error, message, _) = finished(&mut signals, job).await;
        assert_eq!(error, "", "{message}");
        assert_eq!(h.fake.file_data(b"/fifo.bin").as_deref(), Some(&b"streamed"[..]));

        let (mut down_reader, down_writer) = std::io::pipe().unwrap();
        let job = c
            .proxy()
            .download(ACCOUNT_LOC, b"/fifo.bin", Fd::from(down_writer.as_fd()), &no_opts())
            .await
            .unwrap();
        drop(down_writer);
        let (error, message, _) = finished(&mut signals, job).await;
        assert_eq!(error, "", "{message}");
        let mut data = Vec::new();
        // The bridge closed its copy at the end of the job: EOF.
        down_reader.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"streamed");
    });
}

fn fd_validation(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.add_file(b"/a", b"a");
    let dir = TempDir::new();
    let local = temp_file(&dir, "l", b"l");
    block_on(async {
        let c = f.hello_client().await;
        let p = c.proxy();
        let folder = File::open(dir.path()).unwrap();
        let denied = name(ErrorName::PermissionDenied);
        assert_eq!(
            error_name(&p.upload(ACCOUNT_LOC, b"/x", Fd::from(folder.as_fd()), &no_opts()).await),
            denied
        );
        let read_only = File::open(&local).unwrap();
        assert_eq!(
            error_name(&p.download(ACCOUNT_LOC, b"/a", Fd::from(read_only.as_fd()), &no_opts()).await),
            denied
        );
        let write_only = OpenOptions::new().write(true).open(&local).unwrap();
        assert_eq!(
            error_name(&p.upload(ACCOUNT_LOC, b"/x", Fd::from(write_only.as_fd()), &no_opts()).await),
            denied
        );
        // Checked before the location: an unknown one is not looked at.
        assert_eq!(
            error_name(&p.upload("account:9", b"/x", Fd::from(write_only.as_fd()), &no_opts()).await),
            denied
        );
        let (reader, writer) = std::io::pipe().unwrap();
        assert_eq!(
            error_name(&p.upload("account:9", b"/x", Fd::from(reader.as_fd()), &no_opts()).await),
            name(ErrorName::NotFound)
        );
        assert_eq!(
            error_name(&p.download("account:9", b"/x", Fd::from(writer.as_fd()), &no_opts()).await),
            name(ErrorName::NotFound)
        );
        let counters = f.probe().counters().await.unwrap();
        assert_eq!(counters.jobs, 0);
        assert_eq!(h.fake.log_count("connect"), 0); // refused before any network work
        assert!(!h.fake.exists(b"/x"));
    });
}

fn walk_remove_tree_copy_across(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    f.accounts.state().accounts.push(FakeAccounts::fake_account(2));
    f.accounts_changed();
    let fake = h.fake;
    fake.add_file(b"/t/a/1", b"1");
    fake.add_file(b"/t/a/2", b"22");
    fake.add_file(b"/t/b", b"333");
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let probe = f.probe();
        let job = c.proxy().walk(ACCOUNT_LOC, b"/t", &no_opts()).await.unwrap();
        let mut paths = Vec::new();
        loop {
            match wait_signal(&mut signals, WAIT, |s| {
                matches!(s, Signal::WalkBatch { .. } | Signal::JobFinished { .. })
            })
            .await
            {
                Some(Signal::WalkBatch { job: j, entries }) => {
                    assert_eq!(j, job);
                    paths.extend(entries.into_iter().map(|e| String::from_utf8(e.path).unwrap()));
                }
                Some(Signal::JobFinished { job: j, error, extra, .. }) => {
                    assert_eq!((j, error.as_str()), (job, ""));
                    assert_eq!(count(&extra, "entries"), 4);
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        paths.sort();
        assert_eq!(paths, ["/t/a", "/t/a/1", "/t/a/2", "/t/b"]);

        let opts = OptsBuilder::new().bool("recursive", true).build();
        let job = c.proxy().copy_across(ACCOUNT_LOC, b"/t", "account:2", b"/copy", &opts).await.unwrap();
        let (error, message, _) = finished(&mut signals, job).await;
        assert_eq!(error, "", "{message}");
        assert_eq!(fake.file_data(b"/copy/a/2").as_deref(), Some(&b"22"[..]));
        // Again: the target exists.
        let job = c.proxy().copy_across(ACCOUNT_LOC, b"/t", "account:2", b"/copy", &opts).await.unwrap();
        assert_eq!(finished(&mut signals, job).await.0, "AlreadyExists");
        assert_eq!(
            error_name(&c.proxy().copy_across("account:9", b"/t", "account:2", b"/c", &opts).await),
            name(ErrorName::NotFound)
        );
        assert_eq!(
            error_name(&c.proxy().copy_across(ACCOUNT_LOC, b"/t", "account:9", b"/c", &opts).await),
            name(ErrorName::NotFound)
        );

        let job = c.proxy().remove_tree(ACCOUNT_LOC, b"/t").await.unwrap();
        let (error, _, extra) = finished(&mut signals, job).await;
        assert_eq!(error, "");
        assert_eq!((count(&extra, "files"), count(&extra, "dirs")), (3, 2));
        assert!(!fake.exists(b"/t"));
        assert_eq!(error_name(&c.proxy().remove_tree("account:9", b"/t").await), name(ErrorName::NotFound));
        assert_eq!(
            error_name(&c.proxy().walk("account:9", b"/t", &no_opts()).await),
            name(ErrorName::NotFound)
        );
        let counters = probe.wait_until(WAIT, |n| n.jobs == 0 && n.copy_jobs == 0).await.unwrap();
        assert_eq!((counters.jobs, counters.copy_jobs), (0, 0));
    });
}

fn walk_batch_limit(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    for i in 0..700 {
        h.fake.add_file(format!("/w/f{i}").as_bytes(), b"x");
    }
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let job = c.proxy().walk(ACCOUNT_LOC, b"/w", &no_opts()).await.unwrap();
        let mut total = 0;
        loop {
            match wait_signal(&mut signals, WAIT, |s| {
                matches!(s, Signal::WalkBatch { .. } | Signal::JobFinished { .. })
            })
            .await
            {
                Some(Signal::WalkBatch { entries, .. }) => {
                    assert!(entries.len() <= MAX_LIST_BATCH as usize, "{}", entries.len()); // XB-17
                    total += entries.len();
                }
                Some(Signal::JobFinished { job: j, error, .. }) => {
                    assert_eq!((j, error.as_str()), (job, ""));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(total, 700);
    });
}

/// An ad-hoc location of the fake backend (`testing::fake_url`).
const URL: &str = "fake://user@adhoc.example/";
const PIN_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==";
const PIN_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB==";

fn account_identity_changed_sets_attention(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.set_identity_pin(PIN_A);
    f.accounts.state().accounts[0]
        .params
        .options
        .push(("host_key".to_owned(), Value::String(PIN_B.to_owned())));
    f.accounts_changed();
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let stat = c.proxy().stat(ACCOUNT_LOC, b"/", true, "").await;
        assert_eq!(error_name(&stat), name(ErrorName::ServerIdentityChanged));
        assert!(wait_for(WAIT, || !f.accounts.state().attention.is_empty()).await);
        let (id, attention, pin) = f.accounts.state().attention[0].clone();
        assert_eq!((id, attention), (1, Attention::ServerIdentityChanged));
        assert_eq!(pin, PIN_A);
        assert_eq!(h.fake.log_count("authenticate"), 0); // C-7
        // The accounts are listed again (attention) and the consumer told.
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        let questions =
            wait_signal(&mut signals, Duration::from_millis(100), |s| matches!(s, Signal::Question { .. }))
                .await;
        assert!(questions.is_none(), "accounts are resolved in Settings");
        // The helper's data fail: the connection fails with them.
        f.accounts.state().files_error =
            Some(netvfs_bridge::Status::new(ErrorName::NotFound, "No such account"));
        c.proxy().disconnect(ACCOUNT_LOC).await.unwrap();
        let stat = c.proxy().stat(ACCOUNT_LOC, b"/", true, "").await;
        assert_eq!(error_name(&stat), name(ErrorName::NotFound));
    });
}

/// `Answer(id, {accept})`.
async fn answer(c: &Connection, id: &str, accept: bool) {
    c.proxy().answer(id, &OptsBuilder::new().bool("accept", accept).build()).await.unwrap();
}

/// The next question: its id, kind and details.
async fn question(
    signals: &mut SignalStream,
) -> (String, String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) {
    match wait_signal(signals, WAIT, |s| matches!(s, Signal::Question { .. })).await {
        Some(Signal::Question { id, kind, details }) => (id, kind, details),
        other => panic!("{other:?}"),
    }
}

fn ad_hoc_identity_question(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.set_identity_pin(PIN_A);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        // Declined: no credentials are sent.
        let proxy = c.proxy().clone();
        let connecting = tokio::spawn(async move { proxy.connect_ad_hoc(URL, b"", &Opts::new()).await });
        let (id, kind, details) = question(&mut signals).await;
        assert_eq!(kind, "identity-unknown");
        assert_eq!(String::try_from(details["host"].clone()).unwrap(), "adhoc.example");
        assert!(!String::try_from(details["fingerprint"].clone()).unwrap().is_empty());
        assert_eq!(
            error_name(&c.proxy().answer(&id, &OptsBuilder::new().bool("accept", false).build()).await),
            None
        );
        let declined = connecting.await.unwrap();
        assert_eq!(error_name(&declined), name(ErrorName::ServerIdentityUnknown));
        assert_eq!(h.fake.log_count("authenticate"), 0);
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 1);
        assert_eq!(f.probe().counters().await.unwrap().pools, 0);

        // Accepted: pinned in known_hosts; the next connection does not ask.
        let proxy = c.proxy().clone();
        let connecting = tokio::spawn(async move { proxy.connect_ad_hoc(URL, b"", &Opts::new()).await });
        let (id, _, _) = question(&mut signals).await;
        let other = c.proxy().answer("q999", &OptsBuilder::new().bool("accept", true).build()).await;
        assert_eq!(error_name(&other), name(ErrorName::NotFound));
        answer(&c, &id, true).await;
        let loc = connecting.await.unwrap().unwrap();
        assert!(loc.starts_with("adhoc:"), "{loc}");
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        let locations = c.proxy().list_locations().await.unwrap();
        assert_eq!(locations.len(), 2);
        assert_eq!((locations[1].id.as_str(), locations[1].name.as_str()), (loc.as_str(), "adhoc.example"));
        let pin = || KnownHosts::new(f.dir.join("known_hosts")).pin("fake://adhoc.example:0");
        assert_eq!(pin(), PIN_A);
        c.proxy().disconnect(&loc).await.unwrap();
        c.proxy().stat(&loc, b"/", true, "").await.unwrap();
        let asked =
            wait_signal(&mut signals, Duration::from_millis(100), |s| matches!(s, Signal::Question { .. }))
                .await;
        assert!(asked.is_none(), "{asked:?}");

        // A changed identity is an error, not a question (XB-14).
        c.proxy().disconnect(&loc).await.unwrap();
        h.fake.set_identity_pin(PIN_B);
        assert_eq!(
            error_name(&c.proxy().stat(&loc, b"/", true, "").await),
            name(ErrorName::ServerIdentityChanged)
        );
        // ForgetAdHoc drops the location and the pin.
        c.proxy().forget_ad_hoc(&loc).await.unwrap();
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        assert_eq!(pin(), "");
        assert_eq!(error_name(&c.proxy().forget_ad_hoc(&loc).await), name(ErrorName::NotFound));
        assert_eq!(error_name(&c.proxy().forget_ad_hoc(ACCOUNT_LOC).await), name(ErrorName::NotFound));
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 1);
        assert_eq!(error_name(&c.proxy().open_account_settings(&loc).await), name(ErrorName::NotFound));

        // The session goes away while the question is open: no location.
        h.fake.set_identity_pin(PIN_A);
        let c2 = f.hello_client().await;
        let mut signals2 = c2.signals();
        let proxy = c2.proxy().clone();
        let connecting = tokio::spawn(async move { proxy.connect_ad_hoc(URL, b"", &Opts::new()).await });
        let _ = question(&mut signals2).await;
        c2.close().await;
        assert!(connecting.await.unwrap().is_err());
        let probe = f.probe();
        let after =
            probe.wait_until(WAIT, |n| n.questions == 0 && n.requests == 0 && n.sessions == 1).await.unwrap();
        assert_eq!((after.questions, after.requests, after.sessions), (0, 0, 1));
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 1);
    });
}

fn keyboard_interactive(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    h.fake.set_otp(b"123456");
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let proxy = c.proxy().clone();
        let stat = tokio::spawn(async move { proxy.stat(ACCOUNT_LOC, b"/", true, "").await });
        let (id, kind, details) = question(&mut signals).await;
        assert_eq!(kind, "keyboard-interactive");
        assert!(details.contains_key("prompts"));
        let answers =
            OptsBuilder::new().bool("accept", true).byte_arrays("answers", &[b"123456".to_vec()]).build();
        c.proxy().answer(&id, &answers).await.unwrap();
        stat.await.unwrap().unwrap();
        // An answered question is gone.
        assert_eq!(error_name(&c.proxy().answer(&id, &answers).await), name(ErrorName::NotFound));

        // Canceling the request ends the wait: disconnect while the question is open.
        c.proxy().disconnect(ACCOUNT_LOC).await.unwrap();
        let proxy = c.proxy().clone();
        let stat = tokio::spawn(async move { proxy.stat(ACCOUNT_LOC, b"/", true, "").await });
        let (id, _, _) = question(&mut signals).await;
        // Another session cannot answer it.
        let other = f.hello_client().await;
        assert_eq!(error_name(&other.proxy().answer(&id, &answers).await), name(ErrorName::NotFound));
        let probe = f.probe();
        assert_eq!(probe.counters().await.unwrap().questions, 1);
        c.close().await;
        assert!(stat.await.unwrap().is_err());
        let after =
            probe.wait_until(Duration::from_secs(5), |n| n.requests == 0 && n.questions == 0).await.unwrap();
        assert_eq!((after.requests, after.questions), (0, 0));
    });
}

fn connect_ad_hoc_refusals(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let p = c.proxy();
        let refused = p.connect_ad_hoc("sftp://user:pw@host/", b"s", &no_opts()).await;
        assert_eq!(error_name(&refused), name(ErrorName::SecurityPolicy)); // XH-6
        let local = p.connect_ad_hoc("file:///etc", b"", &no_opts()).await;
        assert_eq!(error_name(&local), name(ErrorName::PermissionDenied)); // XB-11: never local paths
        // WebDAV and FTP are gone; their schemes are refused before any backend.
        for url in ["dav://host/", "davs://host/", "ftp://host/", "ftps://host/"] {
            let removed = p.connect_ad_hoc(url, b"", &no_opts()).await;
            assert_eq!(error_name(&removed), name(ErrorName::Unsupported), "{url}");
        }
        let removed = p.connect_ad_hoc("davs://host/", b"", &no_opts()).await.unwrap_err();
        assert_eq!(
            netvfs_bridge_proto::BridgeError::from(removed),
            netvfs_bridge_proto::BridgeError::remote(
                ErrorName::Unsupported,
                "davs URLs are no longer supported"
            )
        );
        let missing = p.connect_ad_hoc("sftp://host/", b"", &no_opts()).await;
        assert_eq!(error_name(&missing), name(ErrorName::Unsupported)); // no sftp backend in the tests
        let bad =
            p.connect_ad_hoc("sftp://host/", b"", &OptsBuilder::new().str("password", "x").build()).await;
        assert_eq!(error_name(&bad).as_deref(), Some("org.freedesktop.DBus.Error.InvalidArgs"));
        let profile = OptsBuilder::new().str("security_profile", "guest").build();
        let not_smb = p.connect_ad_hoc("fake://user@h/", b"", &profile).await;
        assert_eq!(error_name(&not_smb).as_deref(), Some("org.freedesktop.DBus.Error.InvalidArgs"));
        // The user option replaces the URL's: the fake server knows `user` only.
        let user = OptsBuilder::new().str("user", "other").build();
        let wrong = p.connect_ad_hoc("fake://user@h/", b"", &user).await;
        assert_eq!(error_name(&wrong), name(ErrorName::AuthFailed));
        let right = OptsBuilder::new().str("user", "user").build();
        let loc = p.connect_ad_hoc("fake://nobody@h/sub", b"", &right).await.unwrap();
        let locations = p.list_locations().await.unwrap();
        let info = &locations.iter().find(|l| l.id == loc).unwrap().info;
        assert_eq!(String::try_from(info["user"].clone()).unwrap(), "user");
        assert_eq!(f.probe().counters().await.unwrap().requests, 0);
    });
}

fn peer_check_refuses(h: &Harness) {
    let f = Fixture::start(h, Setup { executable: Some("/bin/sh".to_owned()), ..Setup::default() });
    block_on(async {
        // Closed without a reply.
        if let Ok(c) = netvfs_bridge_proto::connect(&f.socket).await {
            assert!(c.proxy().hello(PROTOCOL_VERSION, "x").await.is_err());
        }
        let counters = f.probe().counters().await.unwrap();
        assert_eq!(counters.sessions, 0);
    });
}

fn discovery(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        c.proxy().discover(true).await.unwrap();
        assert_eq!(f.nearby.calls(), [true]);
        let first = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::NearbyChanged(_))).await;
        assert!(matches!(first, Some(Signal::NearbyChanged(ref l)) if l.is_empty()), "{first:?}");
        let server = netvfs_bridge_proto::WireNearby {
            name: "nas".to_owned(),
            provider: "smb".to_owned(),
            host: "nas.local".to_owned(),
            port: 445,
        };
        assert!(f.link().nearby(vec![server.clone()]));
        let found = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::NearbyChanged(_))).await;
        assert!(matches!(found, Some(Signal::NearbyChanged(ref l)) if *l == [server.clone()]), "{found:?}");
        // Another session that does not discover is not told.
        let other = f.hello_client().await;
        let mut other_signals = other.signals();
        assert!(f.link().nearby(vec![]));
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::NearbyChanged(_))).await.is_some());
        let heard = wait_signal(&mut other_signals, Duration::from_millis(400), |s| {
            matches!(s, Signal::NearbyChanged(_))
        })
        .await;
        assert!(heard.is_none(), "{heard:?}");
        c.proxy().discover(false).await.unwrap();
        assert_eq!(f.nearby.calls(), [true, false]); // XD-5
        assert!(!f.probe().counters().await.unwrap().discovering);
        c.proxy().discover(true).await.unwrap();
        assert!(f.probe().counters().await.unwrap().discovering);
        c.close().await;
        let stopped = f.probe().wait_until(WAIT, |n| !n.discovering).await.unwrap();
        assert!(!stopped.discovering);
        assert_eq!(f.nearby.calls(), [true, false, true, false]);
    });
}

const HANDOFF_CONF: &str = "[OpenAccountSettings]\nService=a.b\nPath=/c\nInterface=a.b\nMethod=show\nArguments=i:{accountId}\n[AddAccount]\nService=a.b\nPath=/c\nInterface=a.b\nMethod=add\nArguments=s:{provider}\n";

fn handoff(h: &Harness) {
    let f = Fixture::start(h, Setup { handoff_conf: Some(HANDOFF_CONF.to_owned()), ..Setup::default() });
    block_on(async {
        let c = f.hello_client().await;
        c.proxy().open_account_settings(ACCOUNT_LOC).await.unwrap();
        c.proxy().add_account("smb").await.unwrap();
        let calls = f.launcher.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            (calls[0].method.as_str(), calls[0].arguments.as_slice()),
            ("show", &[HandoffArg::Int(1)][..])
        );
        assert_eq!(calls[1].arguments, [HandoffArg::Str("smb".to_owned())]);
        assert_eq!(error_name(&c.proxy().open_account_settings("adhoc:7").await), name(ErrorName::NotFound));
    });
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        assert_eq!(
            error_name(&c.proxy().open_account_settings(ACCOUNT_LOC).await),
            name(ErrorName::Unsupported)
        );
        assert_eq!(error_name(&c.proxy().add_account("smb").await), name(ErrorName::Unsupported));
        assert!(f.launcher.calls().is_empty());
    });
}

fn locations_changed(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    block_on(async {
        let c = f.hello_client().await;
        let quiet = f.client().await; // no Hello: no signals
        let mut quiet_signals = quiet.signals();
        let mut signals = c.signals();
        f.accounts.state().accounts.push(FakeAccounts::fake_account(5));
        f.accounts_changed();
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 2);
        let heard = wait_signal(&mut quiet_signals, Duration::from_millis(200), |_| true).await;
        assert!(heard.is_none(), "{heard:?}");
        // A pool of an account that is gone goes with it.
        c.proxy().capabilities("account:5").await.unwrap();
        assert_eq!(f.probe().counters().await.unwrap().pools, 1);
        f.accounts.state().accounts.truncate(1);
        f.accounts_changed();
        assert!(wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await.is_some());
        assert_eq!(f.probe().counters().await.unwrap().pools, 0);
        assert_eq!(error_name(&c.proxy().capabilities("account:5").await), name(ErrorName::NotFound));
    });
}

/// The discoveries alive on the Qt thread.
fn live_discoveries(h: &Harness) -> usize {
    let (tx, rx) = std::sync::mpsc::channel();
    assert!(h.ffi.post(move || {
        let _sent = tx.send(nearby::live_discoveries());
    }));
    rx.recv_timeout(WAIT).unwrap()
}

fn ffi_nearby_lives_on_the_qt_thread(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    let mut source = nearby::FfiNearby::new(h.ffi, f.link().clone());
    assert_eq!(live_discoveries(h), 0);
    source.set_running(false); // nothing to stop: nothing made
    assert_eq!(live_discoveries(h), 0);
    source.set_running(true);
    assert_eq!(live_discoveries(h), 1);
    source.set_running(false); // stopped, kept for the next start
    assert_eq!(live_discoveries(h), 1);
    source.set_running(true);
    assert_eq!(live_discoveries(h), 1);
    drop(source);
    assert_eq!(live_discoveries(h), 0);
}

fn cancel_copy_across(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    f.accounts.state().accounts.push(FakeAccounts::fake_account(2));
    f.accounts_changed();
    h.fake.add_file(b"/big", &vec![b'x'; 4 << 20]);
    h.fake.set_chunk_delay_ms(50);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let probe = f.probe();
        let job =
            c.proxy().copy_across(ACCOUNT_LOC, b"/big", "account:2", b"/copy", &no_opts()).await.unwrap();
        assert_eq!(probe.wait_until(WAIT, |n| n.copy_jobs == 1).await.unwrap().copy_jobs, 1);
        let progress = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::JobProgress { .. })).await;
        assert!(matches!(progress, Some(Signal::JobProgress { job: j, .. }) if j == job), "{progress:?}");
        c.proxy().cancel(job).await.unwrap();
        assert_eq!(finished(&mut signals, job).await.0, "Canceled");
        let after = probe.wait_until(WAIT, |n| n.copy_jobs == 0 && n.jobs == 0).await.unwrap();
        assert_eq!((after.copy_jobs, after.jobs), (0, 0));
    });
}

fn cancel_pending_job(h: &Harness) {
    let f = Fixture::new(h, Consent::Granted);
    let mut accounts = f.accounts.state();
    accounts.accounts.push(FakeAccounts::fake_account(2));
    accounts.accounts.push(FakeAccounts::fake_account(3));
    drop(accounts);
    f.accounts_changed();
    h.fake.add_file(b"/big", &vec![b'x'; 4 << 20]);
    h.fake.set_chunk_delay_ms(50);
    block_on(async {
        let c = f.hello_client().await;
        let mut signals = c.signals();
        let probe = f.probe();
        let started = Instant::now();
        while c.proxy().list_locations().await.unwrap().len() < 3 {
            assert!(started.elapsed() < WAIT, "accounts 2 and 3 never came");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The host's connections (POOL_PER_HOST), each stuck on a pipe
        // nobody reads: two of account 1, two of account 2.
        let mut pipes = Vec::new();
        let mut download = async |loc: &str| {
            let (reader, writer) = std::io::pipe().unwrap();
            let job = c.proxy().download(loc, b"/big", Fd::from(writer.as_fd()), &no_opts()).await.unwrap();
            pipes.push(reader);
            job
        };
        for loc in [ACCOUNT_LOC, ACCOUNT_LOC, "account:2", "account:2"] {
            download(loc).await;
        }
        assert_eq!(POOL_PER_HOST, 4);
        // Account 3 has no connection and the host none to spare: it waits.
        let pending = download("account:3").await;
        assert_eq!(probe.wait_until(WAIT, |n| n.jobs == 5).await.unwrap().jobs, 5);
        c.proxy().cancel(pending).await.unwrap();
        // XB-13: waiting work ends at once, not when a connection comes free.
        assert_eq!(finished(&mut signals, pending).await.0, "Canceled");
        assert_eq!(probe.wait_until(WAIT, |n| n.jobs == 4).await.unwrap().jobs, 4);
        drop(pipes);
    });
}

fn idle_exit_after_an_answer(h: &Harness) {
    let mut f = Fixture::with_idle_exit(h, Consent::Unknown, Duration::from_millis(300));
    block_on(async {
        let c = f.hello_client().await;
        assert_eq!(f.prompt.state().shown, 1);
        c.close().await;
        drop(c);
        // The answer is stored after the consumer left; then the bridge goes.
        f.answer_prompt(false);
        assert_eq!(f.wait_exit(Duration::from_secs(5)).await, Some(ExitCode::SUCCESS));
        assert_eq!(f.stored_consent(), Consent::Denied);
    });
}

fn debug_output(h: &Harness) {
    let mut f = Fixture::new(h, Consent::Granted);
    let link = f.link().clone();
    assert_eq!(format!("{link:?}"), "CoreLink { closed: false }");
    let services = Services {
        accounts: Rc::new(f.accounts.clone()),
        prompt: Box::new(f.prompt.clone()),
        nearby: Box::new(f.nearby.clone()),
        launcher: Box::new(f.launcher.clone()),
    };
    assert_eq!(format!("{services:?}"), "Services { prompt_shown: false, .. }");
    let deps = Deps {
        ffi: h.ffi,
        listen: ListenAddress::parse("unix:path=/nowhere").unwrap(),
        services: Box::new(|_| panic!("never served")),
        url_override: None,
    };
    let text = format!("{deps:?}");
    assert!(text.starts_with("Deps { ffi: ") && text.ends_with("url_override: false, .. }"), "{text}");
    assert!(text.contains("/nowhere"), "{text}");
    assert_eq!(f.stop(), Some(ExitCode::SUCCESS));
    assert_eq!(format!("{link:?}"), "CoreLink { closed: true }");
}
