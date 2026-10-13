// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `netvfs-bridge` binary (SPEC-v2 XB-2): its command line and exit
//! codes, and with the C ABI (the variables of `tests/ffi.rs`) a run that
//! serves a client on `--listen unix:path=…` and ends with the idle exit.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::assertions_on_result_states
)]

use netvfs_bridge::testutil::TempDir;
use netvfs_bridge_proto::PROTOCOL_VERSION;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BRIDGE: &str = env!("CARGO_BIN_EXE_netvfs-bridge");
const FFI_VARIABLES: [&str; 2] = ["NETVFS_BRIDGE_FFI", "NETVFS_BACKEND_PATH"];

/// The bridge with a private home and consumers folder in `dir`.
fn bridge(dir: &TempDir, args: &[&str]) -> Command {
    let mut command = Command::new(BRIDGE);
    command
        .args(args)
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("NETVFS_CONSUMERS_DIR", dir.join("consumers"))
        .env("NETVFS_ACCOUNTS_HELPER", dir.join("no-helper"))
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_PID")
        .stdin(Stdio::null());
    command
}

fn run(dir: &TempDir, args: &[&str]) -> Output {
    bridge(dir, args).output().expect("netvfs-bridge runs")
}

/// Registers consumer `id` with this test binary as its executable.
fn register(dir: &TempDir, id: &str) {
    let exe = std::env::current_exe().unwrap();
    let conf = format!(
        "[Consumer]\nId={id}\nDisplayName=Process test\nExecutable={}\nDataDir=.local/share/{id}\n",
        exe.display()
    );
    dir.write(&format!("consumers/{id}.conf"), conf);
    std::fs::create_dir_all(dir.join("home")).unwrap();
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn usage_errors_exit_with_2() {
    let dir = TempDir::new();
    for args in
        [&[][..], &["a", "b"], &["--listen", "x"], &["--other", "x", "a"], &["--listen", "x", "a", "b"]]
    {
        let output = run(&dir, args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(stderr(&output), "usage: netvfs-bridge [--listen DBUS-ADDRESS] <consumer-id>\n");
    }
}

#[test]
fn an_unknown_consumer_fails() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.join("consumers")).unwrap();
    let output = run(&dir, &["nobody"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("nobody"), "{}", stderr(&output));
    let output = run(&dir, &["Not/Valid"]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn a_bad_listen_address_fails() {
    let dir = TempDir::new();
    register(&dir, "proc-test");
    let output = run(&dir, &["--listen", "tcp:host=x", "proc-test"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Cannot listen on tcp:host=x"), "{}", stderr(&output));
}

#[test]
fn a_missing_c_abi_fails() {
    let dir = TempDir::new();
    register(&dir, "proc-test");
    let socket = format!("unix:path={}", dir.join("bridge.sock").display());
    let output = bridge(&dir, &["--listen", &socket, "proc-test"])
        .env("NETVFS_BRIDGE_FFI", dir.join("missing.so"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("Cannot load the backends"), "{}", stderr(&output));
}

fn wait_for_socket(path: &Path) {
    let end = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < end, "no socket at {}", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn serves_and_exits_when_idle() {
    if FFI_VARIABLES.iter().any(|v| std::env::var_os(v).is_none()) {
        println!("skipped: {} not set (make check-rust-ffi sets them)", FFI_VARIABLES.join(", "));
        return;
    }
    let dir = TempDir::new();
    register(&dir, "proc-test");
    dir.write("config/netvfs/bridge.conf", "[Consent]\nproc-test=granted\n");
    let socket = dir.join("bridge.sock");
    let listen = format!("unix:path={}", socket.display());
    let mut child = bridge(&dir, &["--listen", &listen, "proc-test"])
        .env("NETVFS_BRIDGE_IDLE_EXIT_MS", "500")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_socket(&socket);
    let started = Instant::now();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let c = netvfs_bridge_proto::connect(&socket).await.unwrap();
        c.proxy().hello(PROTOCOL_VERSION, "process").await.unwrap();
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        // No helper: no accounts.
        assert!(c.proxy().list_locations().await.unwrap().is_empty());
        tokio::time::sleep(Duration::from_millis(800)).await;
        // Still there while a consumer is connected.
        assert_eq!(c.proxy().get_consent().await.unwrap(), "granted");
        c.close().await;
    });
    let end = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < end, "no idle exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0));
    assert!(started.elapsed() >= Duration::from_millis(1200), "{:?}", started.elapsed());
}
