// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `netvfs-bridge` binary (SPEC-v2 XB-2; C++ `tst_bridgeprocess`): its
//! command line and exit codes, and with the C ABI (the variables of
//! `tests/ffi.rs`) runs that serve a client on `--listen unix:path=…` and
//! on a socket passed as systemd does, and end with the idle exit. Every
//! bridge started here dies with its test ([`TestChild`]).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::assertions_on_result_states
)]

use netvfs_bridge::accounts::watch;
use netvfs_bridge::consent::Consent;
use netvfs_bridge::testing::{BridgeRun, WAIT, wait_signal};
use netvfs_bridge::testutil::{TestBus, TestChild};
use netvfs_bridge_proto::{PROTOCOL_VERSION, Signal};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

const BRIDGE: &str = env!("CARGO_BIN_EXE_netvfs-bridge");
const HELPER: &str = env!("CARGO_BIN_EXE_netvfs-accounts-fake");
const FFI_VARIABLES: [&str; 2] = ["NETVFS_BRIDGE_FFI", "NETVFS_BACKEND_PATH"];
/// How long a bridge may take to end.
const EXIT_WAIT: Duration = Duration::from_secs(10);

/// Whether the C ABI is there; says the test is skipped when not.
fn have_ffi() -> bool {
    let missing = FFI_VARIABLES.iter().any(|v| std::env::var_os(v).is_none());
    if missing {
        println!("skipped: {} not set (make check-rust-ffi sets them)", FFI_VARIABLES.join(", "));
    }
    !missing
}

/// Runs `args` for consumer `proc-test` (registered) until it ends: exit
/// code and stderr.
fn run(args: &[&str], ffi: Option<&Path>) -> (Option<i32>, String) {
    let mut run = BridgeRun::bare(Path::new(BRIDGE), "proc-test");
    run.command.args(args).stdout(Stdio::null()).stderr(Stdio::piped());
    if let Some(ffi) = ffi {
        run.command.env("NETVFS_BRIDGE_FFI", ffi);
    }
    let mut child = TestChild::spawn(&mut run.command).unwrap();
    let status = child.wait_timeout(EXIT_WAIT).expect("netvfs-bridge ends");
    let mut stderr = String::new();
    child.child().stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    (status.code(), stderr)
}

#[test]
fn usage_errors_exit_with_2() {
    for args in
        [&[][..], &["a", "b"], &["--listen", "x"], &["--other", "x", "a"], &["--listen", "x", "a", "b"]]
    {
        let (code, stderr) = run(args, None);
        assert_eq!(code, Some(2), "{args:?}");
        assert_eq!(stderr, "usage: netvfs-bridge [--listen DBUS-ADDRESS] <consumer-id>\n");
    }
}

#[test]
fn an_unknown_consumer_fails() {
    let (code, stderr) = run(&["nobody"], None);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("nobody"), "{stderr}");
    let (code, _) = run(&["Not/Valid"], None);
    assert_eq!(code, Some(1));
}

#[test]
fn a_bad_listen_address_fails() {
    let (code, stderr) = run(&["--listen", "tcp:host=x", "proc-test"], None);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("Cannot listen on tcp:host=x"), "{stderr}");
}

#[test]
fn a_missing_c_abi_fails() {
    let dir = netvfs_bridge::testutil::TempDir::new();
    let socket = format!("unix:path={}", dir.join("bridge.sock").display());
    let (code, stderr) = run(&["--listen", &socket, "proc-test"], Some(&dir.join("missing.so")));
    assert_eq!(code, Some(1));
    assert!(stderr.contains("Cannot load the backends"), "{stderr}");
}

#[test]
fn not_activated_fails() {
    // `systemd:` (no --listen) without LISTEN_PID and LISTEN_FDS.
    if !have_ffi() {
        return;
    }
    let (code, stderr) = run(&["proc-test"], None);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("not socket-activated"), "{stderr}");
}

/// Waits for the bridge to end by itself: its exit code, and how long
/// that took from `since`.
fn idle_exit(child: &mut TestChild, since: Instant) -> (Option<i32>, Duration) {
    let status = child.wait_timeout(EXIT_WAIT).expect("no idle exit");
    (status.code(), since.elapsed())
}

#[test]
fn serves_and_exits_when_idle() {
    if !have_ffi() {
        return;
    }
    let mut run = BridgeRun::new(Path::new(BRIDGE), "proc-test");
    run.with_consent(Consent::Granted);
    let mut child = run.spawn();
    let started = Instant::now();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let c = run.client().await;
        c.proxy().hello(PROTOCOL_VERSION, "process").await.unwrap();
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        // No helper: no accounts.
        assert!(c.proxy().list_locations().await.unwrap().is_empty());
        tokio::time::sleep(Duration::from_millis(800)).await;
        // Still there while a consumer is connected.
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        c.close().await;
    });
    let (code, took) = idle_exit(&mut child, started);
    assert_eq!(code, Some(0), "{}", run.log());
    assert!(took >= Duration::from_millis(1200), "{took:?}");
}

#[test]
fn exits_when_idle_without_a_client() {
    if !have_ffi() {
        return;
    }
    let mut run = BridgeRun::new(Path::new(BRIDGE), "proc-test");
    let started = Instant::now();
    let mut child = run.spawn();
    let (code, took) = idle_exit(&mut child, started);
    assert_eq!(code, Some(0), "{}", run.log());
    assert!(took >= Duration::from_millis(500), "{took:?}");
}

#[test]
fn exits_cleanly_with_a_session_bus() {
    // The session-bus connection outlives the core: it must be dropped
    // inside the runtime, or zbus panics as the bridge leaves.
    if !have_ffi() {
        return;
    }
    let Some(bus) = TestBus::start() else {
        println!("skipped: no dbus-daemon");
        return;
    };
    let mut run = BridgeRun::new(Path::new(BRIDGE), "proc-test");
    run.with_session_bus(bus.address());
    let started = Instant::now();
    let mut child = run.spawn();
    let (code, _) = idle_exit(&mut child, started);
    assert_eq!(code, Some(0), "{}", run.log());
}

#[test]
fn exits_when_idle_after_a_client_vanished() {
    // A client that ends without a word (killed): the bridge sees the
    // connection close and still leaves after the idle time, also with a
    // listing in flight.
    if !have_ffi() {
        return;
    }
    let mut run = BridgeRun::new(Path::new(BRIDGE), "proc-test");
    run.with_consent(Consent::Granted).with_fake_accounts(Path::new(HELPER));
    let files: Vec<(Vec<u8>, &[u8])> =
        (0..200).map(|i| (format!("/many/f{i:03}").into_bytes(), &b"x"[..])).collect();
    let files: Vec<(&[u8], &[u8])> = files.iter().map(|(p, c)| (p.as_slice(), *c)).collect();
    run.with_files(&files);
    let mut child = run.spawn();
    // The client goes with its runtime, without closing the connection and
    // while the bridge streams a listing to it.
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let c = run.client().await;
        c.proxy().hello(PROTOCOL_VERSION, "process").await.unwrap();
        let mut signals = c.signals();
        let req = c.proxy().list("account:1", b"/many", "", 1).await.unwrap();
        let batch =
            wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::ListBatch { req: r, .. } if *r == req));
        assert!(batch.await.is_some(), "{}", run.log());
    });
    let (code, _) = idle_exit(&mut child, Instant::now());
    assert_eq!(code, Some(0), "{}", run.log());
}

// tst_bridgeprocess socketActivation: started as systemd starts it.
#[test]
fn socket_activation() {
    if !have_ffi() {
        return;
    }
    let mut run = BridgeRun::activated(Path::new(BRIDGE), "proc-test");
    run.with_consent(Consent::Granted).with_fake_accounts(Path::new(HELPER));
    run.with_files(&[(b"/hello.txt", b"hello")]);
    let mut child = run.spawn();
    let started = Instant::now();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let c = run.client().await;
        let (protocol, _, _) = c.proxy().hello(PROTOCOL_VERSION, "process").await.unwrap();
        assert_eq!(protocol, PROTOCOL_VERSION);
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        let locations = c.proxy().list_locations().await.unwrap();
        assert_eq!(locations.len(), 1, "{locations:?}");
        let l = &locations[0];
        assert_eq!((l.id.as_str(), l.provider.as_str(), l.name.as_str()), ("account:1", "fake", "Fake 1"));
        assert_eq!(String::try_from(l.info["host"].try_clone().unwrap()).unwrap(), "fake.example");
        // The account's files, through the helper's access data and the
        // seeded fake server.
        let entry = c.proxy().stat("account:1", b"/hello.txt", true, "").await.unwrap();
        assert_eq!((entry.name.as_slice(), entry.size), (&b"hello.txt"[..], 5));
        c.close().await;
    });
    // XB-2: gone after the idle time with no client and no job.
    let (code, took) = idle_exit(&mut child, started);
    assert_eq!(code, Some(0), "{}", run.log());
    assert!(took >= Duration::from_millis(500), "{took:?}");
    // XB-4: the bridge wrote nothing into the consumer's folder.
    assert!(!run.dir.join("home/.local/share/proc-test").exists());
    assert!(std::fs::read_dir(run.dir.join("home")).unwrap().next().is_none());
}

// The installed bridge's services on a session bus (Deps::system): an
// account change that libaccounts announces there reaches the consumer,
// every time.
#[test]
fn account_changes_on_the_session_bus() {
    if !have_ffi() {
        return;
    }
    let Some(bus) = TestBus::start() else {
        println!("skipped: no dbus-daemon");
        return;
    };
    let mut run = BridgeRun::new(Path::new(BRIDGE), "proc-test");
    run.with_consent(Consent::Granted).with_fake_accounts(Path::new(HELPER)).with_session_bus(bus.address());
    let _child = run.spawn();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let writer = bus.connect().await;
        let c = run.client().await;
        c.proxy().hello(PROTOCOL_VERSION, "process").await.unwrap();
        let mut signals = c.signals();
        assert_eq!(c.proxy().list_locations().await.unwrap().len(), 1);
        for id in [2, 3] {
            let mut table = std::fs::OpenOptions::new().append(true).open(run.dir.join("accounts")).unwrap();
            writeln!(table, "account\t{id}\tfake\tFake {id}\tfake.example\t0\tuser\t/\t").unwrap();
            drop(table);
            writer
                .emit_signal(None::<&str>, "/ServiceType/files", watch::INTERFACE, watch::MEMBER, &())
                .await
                .unwrap();
            let changed = wait_signal(&mut signals, WAIT, |s| matches!(s, Signal::LocationsChanged)).await;
            assert!(changed.is_some(), "account {id}: {}", run.log());
            let ids: Vec<String> =
                c.proxy().list_locations().await.unwrap().into_iter().map(|l| l.id).collect();
            assert_eq!(ids.len(), usize::try_from(id).unwrap(), "{ids:?}");
            assert!(ids.contains(&format!("account:{id}")), "{ids:?}");
        }
    });
}
