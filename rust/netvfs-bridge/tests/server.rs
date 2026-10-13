// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bridge end to end (design §4.1, chunk E): the core with the socket
//! front, in-process ([`Fixture`]), against the real
//! `libnetvfs-bridge-ffi.so` and the fake backend, through the protocol
//! crate's client. The Rust side of `tests/bridge/server/tst_bridgeserver.cpp`.
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

use netvfs_bridge::consent::Consent;
use netvfs_bridge::testing::{
    self, ACCOUNT_LOC, Fixture, Harness, Test, WAIT, block_on, error_name, wait_disconnected, wait_signal,
};
use netvfs_bridge_proto::zvariant::Fd;
use netvfs_bridge_proto::{ErrorName, Opts, PROTOCOL_VERSION, Signal};
use std::os::fd::AsFd as _;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const TESTS: &[(&str, Test)] = &[
    ("hello_first", hello_first),
    ("hello_and_locations", hello_and_locations),
    ("consent_unknown_then_granted", consent_unknown_then_granted),
    ("consent_denied", consent_denied),
    ("revocation_mid_job", revocation_mid_job),
    ("list_streams_batches", list_streams_batches),
    ("cancel_job", cancel_job),
    ("disconnect_cancels_jobs", disconnect_cancels_jobs),
    ("idle_exit", idle_exit),
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
async fn slow_download(f: &Fixture, c: &netvfs_bridge_proto::Connection) -> (u32, std::io::PipeReader) {
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
        assert_eq!(counters.requests, 0);
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
        let counters = f.probe().wait_until(WAIT, |n| n.jobs == 0).await.unwrap();
        assert_eq!(counters.jobs, 0);
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
