// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C ABI through `netvfs_bridge::ffi`, against the real
//! `libnetvfs-bridge-ffi.so` (`NETVFS_BRIDGE_FFI`) with the fake backend
//! (`NETVFS_BACKEND_PATH`, provider "fake") steered through
//! `libnetvfs-bridge-ffi-fake.so` (`NETVFS_BRIDGE_FFI_FAKE`); design §4.1,
//! the Rust side of `tests/bridge/ffi/tst_bridgeffi.cpp`. `make
//! check-rust-ffi` sets the variables; without them every test says it is
//! skipped and passes, so that a plain `cargo nextest` needs no C++ build.
//!
//! Its own harness: `init` must run on the main thread, which then serves
//! the Qt event loop (T1). It speaks enough of libtest's command line for
//! nextest (`--list --format terse`, `<name> --exact`), which runs each
//! test in a process of its own; `cargo test` runs them all in one.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use netvfs_bridge::Status;
use netvfs_bridge::ffi::fake::{self, Fake};
use netvfs_bridge::ffi::{
    Attributes, Conn, Discovery, EstablishError, EstablishHooks, Ffi, Identity, IdentityKind, LoadError,
    Params, Phase, Progress, PromptRequest, ReadAt, Reply, Secret, TreeCounts, UploadOptions, Value, Verdict,
    WalkOptions, WriteAt, library_path, take_orphan_panics,
};
use netvfs_bridge_proto::{ErrorName, WireEntry, entry_kind};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

// ------------------------------------------------------------- harness

#[derive(Clone, Copy)]
struct Env {
    ffi: Ffi,
    fake: Fake,
}

type Test = fn(&Env);

const TESTS: &[(&str, Test)] = &[
    ("loading_and_version", loading_and_version),
    ("conn_lifecycle", conn_lifecycle),
    ("establish_identity_verdicts", establish_identity_verdicts),
    ("establish_prompt_replies", establish_prompt_replies),
    ("establish_phases", establish_phases),
    ("establish_signon_off_qt_thread", establish_signon_off_qt_thread),
    ("list_batches_and_stop", list_batches_and_stop),
    ("walk_visit_and_stop", walk_visit_and_stop),
    ("remove_tree_counts", remove_tree_counts),
    ("metadata_and_namespace", metadata_and_namespace),
    ("handles_read_eof", handles_read_eof),
    ("upload_download_via_io", upload_download_via_io),
    ("cancel_from_other_thread_during_list", cancel_from_other_thread_during_list),
    ("copy_across_two_conns", copy_across_two_conns),
    ("url_parse_format", url_parse_format),
    ("error_mapping", error_mapping),
    ("post_and_quit", post_and_quit),
    ("callback_panics_do_not_unwind", callback_panics_do_not_unwind),
    ("calls_from_callbacks_refused", calls_from_callbacks_refused),
    ("discovery_start_stop", discovery_start_stop),
    ("results_are_freed", results_are_freed),
];

/// A test that runs longer than this hangs: the process says so and ends.
/// The slowest takes about 7 s under ASan, printing backtraces of panics.
const HANG: Duration = Duration::from_secs(30);

const VARIABLES: [&str; 3] = ["NETVFS_BRIDGE_FFI", fake::PATH_ENV, "NETVFS_BACKEND_PATH"];

impl Env {
    /// `None` when the libraries are not named.
    fn load() -> Option<Self> {
        if VARIABLES.iter().any(|v| std::env::var_os(v).is_none()) {
            return None;
        }
        let ffi = Ffi::load().unwrap_or_else(|e| panic!("{e}"));
        let Some(fake) = Fake::from_env() else { panic!("{} is set but not seen", fake::PATH_ENV) };
        let fake = fake.unwrap_or_else(|e| panic!("{e}"));
        Some(Self { ffi, fake })
    }
}

fn selected(args: &[String]) -> Vec<(&'static str, Test)> {
    let exact = args.iter().any(|a| a == "--exact");
    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    TESTS
        .iter()
        .copied()
        .filter(|(name, _)| {
            filters.is_empty()
                || filters.iter().any(|f| if exact { name == f } else { name.contains(f.as_str()) })
        })
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--list") {
        if !args.iter().any(|a| a == "--ignored") {
            for (name, _) in TESTS {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    let tests = selected(&args);
    let Some(env) = Env::load() else {
        println!("skipped: {} not set (make check-rust-ffi sets them)", VARIABLES.join(", "));
        return ExitCode::SUCCESS;
    };
    // T1: first of all, on the main thread.
    env.ffi.init("netvfs-bridge-ffi-test").unwrap();
    let mut failed = 0;
    for (name, test) in tests {
        env.fake.reset();
        let watchdog = watch(name);
        let ok = catch_unwind(AssertUnwindSafe(|| test(&env))).is_ok();
        drop(watchdog);
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        failed += usize::from(!ok);
    }
    env.ffi.shutdown().unwrap();
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Ends the process when the test is not done within [`HANG`]: a test
/// waiting for the event loop would otherwise wait for good. Dropping the
/// sender says it is done.
#[allow(clippy::exit)]
fn watch(name: &'static str) -> mpsc::Sender<()> {
    let (done, finished) = mpsc::channel::<()>();
    thread::spawn(move || {
        if finished.recv_timeout(HANG) == Err(mpsc::RecvTimeoutError::Timeout) {
            println!("test {name} ... FAILED (hung for {HANG:?})");
            std::process::exit(2);
        }
    });
    done
}

// ------------------------------------------------------------- helpers

/// Quits the event loop when it goes, also when the work panicked.
struct QuitOnDrop(Ffi);

impl Drop for QuitOnDrop {
    fn drop(&mut self) {
        self.0.quit(0);
    }
}

/// Waits until the Qt event loop runs a posted function.
fn wait_for_loop(ffi: Ffi) {
    let (tx, rx) = mpsc::channel();
    // Refused while the loop of an earlier run is quitting.
    loop {
        let tx = tx.clone();
        if ffi.post(move || tx.send(()).unwrap()) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    rx.recv().unwrap();
}

/// Runs `work` on another thread while this one runs the Qt event loop
/// (the bridge's layout: workers block, the main thread serves signond).
fn off_qt_thread<R: Send>(env: &Env, work: impl FnOnce() -> R + Send) -> R {
    let ffi = env.ffi;
    thread::scope(|s| {
        let worker = s.spawn(move || {
            let _quit = QuitOnDrop(ffi);
            wait_for_loop(ffi);
            work()
        });
        assert_eq!(ffi.run(), Ok(0));
        worker.join().unwrap()
    })
}

fn params() -> Params {
    Params {
        provider: "fake".into(),
        host: "fake.example".into(),
        username: "user".into(),
        connect_timeout_ms: 15000,
        request_timeout_ms: 60000,
        ..Params::default()
    }
}

fn secret(pw: &[u8]) -> Secret {
    Secret::Bytes { user: "user".into(), secret: Zeroizing::new(pw.to_vec()) }
}

fn establish(conn: &mut Conn, pin: &str, secret: &Secret) -> Result<(), EstablishError> {
    conn.establish(&params(), pin, secret, &mut EstablishHooks::default())
}

fn connected(env: &Env) -> Conn {
    let mut conn = env.ffi.conn_new("fake").unwrap();
    establish(&mut conn, "", &secret(b"secret")).unwrap();
    conn
}

fn name_of<T>(r: &Result<T, Status>) -> Option<ErrorName> {
    r.as_ref().err().map(|s| s.name)
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            let c = if i <= chunk.len() { ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] } else { b'=' };
            out.push(char::from(c));
        }
    }
    out
}

fn pin_for(key: &[u8]) -> String {
    format!("ssh-ed25519 {}", base64(key))
}

fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|i| u8::try_from((i * 7 + i / 251) & 0xff).unwrap()).collect()
}

/// Progress that counts, and stops after `cancel_after` updates.
#[derive(Default)]
struct Ticks {
    updates: Vec<(i64, i64)>,
    cancel_after: Option<usize>,
    panic: bool,
}

impl Progress for Ticks {
    fn update(&mut self, done: i64, total: i64) {
        assert!(!self.panic, "progress broke");
        self.updates.push((done, total));
    }

    fn canceled(&mut self) -> bool {
        self.cancel_after.is_some_and(|n| self.updates.len() >= n)
    }
}

/// The local side of a transfer: memory, written in short pieces.
#[derive(Default)]
struct Memory {
    data: Vec<u8>,
    max_write: Option<usize>,
    fail_writes: bool,
    panic_on_read: bool,
    writes: usize,
}

impl ReadAt for Memory {
    fn read_at(&mut self, pos: i64, buf: &mut [u8]) -> Option<usize> {
        assert!(!self.panic_on_read, "read broke");
        let start = usize::try_from(pos).ok()?.min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Some(n)
    }
}

impl WriteAt for Memory {
    fn write_at(&mut self, pos: i64, data: &[u8]) -> Option<usize> {
        self.writes += 1;
        if self.fail_writes {
            return None;
        }
        let n = self.max_write.map_or(data.len(), |m| m.min(data.len()));
        let pos = usize::try_from(pos).ok()?;
        if self.data.len() < pos + n {
            self.data.resize(pos + n, 0);
        }
        self.data[pos..pos + n].copy_from_slice(&data[..n]);
        Some(n)
    }
}

fn names(batch: &[WireEntry]) -> Vec<Vec<u8>> {
    batch.iter().map(|e| e.name.clone()).collect()
}

// --------------------------------------------------------------- tests

fn loading_and_version(env: &Env) {
    let path = library_path();
    assert_eq!(Ffi::load_requesting(&path, 2).unwrap_err(), LoadError::VersionRefused { version: 2 });
    assert_eq!(Ffi::load_requesting(&path, 0).unwrap_err(), LoadError::VersionRefused { version: 0 });
    let again = Ffi::load_from(&path).unwrap();
    assert_eq!(usize::try_from(again.struct_size()).unwrap(), size_of::<netvfs_bridge::ffi::raw::NvbFfiV1>());
    // The fake's library has no nvb_ffi_get, and a missing one does not load.
    let fake_path = PathBuf::from(std::env::var_os(fake::PATH_ENV).unwrap());
    assert!(
        matches!(Ffi::load_from(&fake_path), Err(LoadError::NoEntry { entry, .. }) if entry == "nvb_ffi_get")
    );
    assert!(matches!(Ffi::load_from(&fake_path.with_file_name("nothing.so")), Err(LoadError::Open { .. })));
    // T1: init once, on the main thread; run and shutdown only there.
    assert!(env.ffi.on_qt_thread());
    assert_eq!(name_of(&env.ffi.init("again")), Some(ErrorName::Internal));
    let ffi = env.ffi;
    thread::spawn(move || {
        assert!(!ffi.on_qt_thread());
        let refused = ffi.init("worker").unwrap_err();
        assert_eq!(
            (refused.name, refused.message.as_str()),
            (ErrorName::Internal, "init must run on the main thread")
        );
        assert_eq!(name_of(&ffi.run()), Some(ErrorName::Internal));
        assert_eq!(name_of(&ffi.shutdown()), Some(ErrorName::Internal));
    })
    .join()
    .unwrap();
    assert!(format!("{ffi:?}").starts_with("Ffi { version: 1"));
    assert!(format!("{:?}", env.fake).starts_with("Fake"));
}

fn conn_lifecycle(env: &Env) {
    let f = env.fake;
    assert_eq!(name_of(&env.ffi.conn_new("nosuchprovider")), Some(ErrorName::Unsupported));
    assert!(env.ffi.provider_available("fake"));
    assert!(!env.ffi.provider_available("nosuchprovider"));

    let mut conn = connected(env);
    let cancel = conn.cancel_handle();
    assert_eq!(f.live_backends(), 1);
    f.add_file(b"/a", b"0123456789");
    let (handle, size) = conn.open_read(b"/a").unwrap();
    assert_eq!(size, 10);
    // The handle keeps the connection: nothing is closed yet (O4).
    drop(conn);
    assert_eq!((f.live_backends(), f.log_count("close:a"), f.log_count("disconnect")), (1, 0, 0));
    assert!(format!("{cancel:?}").contains("live: true"));
    drop(handle);
    assert_eq!((f.log_count("close:a"), f.live_backends(), f.log_count("disconnect")), (1, 0, 1));
    // T4: a cancel after conn_free does nothing.
    assert!(!cancel.cancel());
    assert!(format!("{cancel:?}").contains("live: false"));

    // conn_free disconnects an idle connection.
    let conn = connected(env);
    assert!(format!("{conn:?}").starts_with("Conn"));
    drop(conn);
    assert_eq!((f.live_backends(), f.log_count("disconnect")), (0, 2));
}

struct IdentityCase {
    name: &'static str,
    pin_key: Option<&'static [u8]>,
    verdict: Verdict,
    check: Option<ErrorName>,
    error: Option<ErrorName>,
}

fn establish_identity_verdicts(env: &Env) {
    let f = env.fake;
    let unknown = Some(ErrorName::ServerIdentityUnknown);
    let changed = Some(ErrorName::ServerIdentityChanged);
    let cases = [
        IdentityCase {
            name: "pinned",
            pin_key: Some(b"k1"),
            verdict: Verdict::UseCheck,
            check: None,
            error: None,
        },
        IdentityCase {
            name: "unknown",
            pin_key: None,
            verdict: Verdict::UseCheck,
            check: unknown,
            error: unknown,
        },
        IdentityCase {
            name: "accepted",
            pin_key: None,
            verdict: Verdict::AcceptUnknown,
            check: unknown,
            error: None,
        },
        IdentityCase {
            name: "changed, accept ignored",
            pin_key: Some(b"k2"),
            verdict: Verdict::AcceptUnknown,
            check: changed,
            error: changed,
        },
        IdentityCase {
            name: "canceled",
            pin_key: Some(b"k1"),
            verdict: Verdict::Cancel,
            check: None,
            error: Some(ErrorName::Canceled),
        },
    ];
    for case in cases {
        f.reset();
        f.set_identity_pin(&pin_for(b"k1"));
        let mut seen: Vec<(Identity, Option<ErrorName>, i32)> = Vec::new();
        let mut identity = |id: &Identity, check: Option<&Status>| {
            seen.push((id.clone(), check.map(|s| s.name), f.log_count("authenticate")));
            case.verdict
        };
        let mut hooks = EstablishHooks { identity: Some(&mut identity), prompt: None };
        let mut conn = env.ffi.conn_new("fake").unwrap();
        let pin = case.pin_key.map(pin_for).unwrap_or_default();
        let result = conn.establish(&params(), &pin, &secret(b"secret"), &mut hooks);
        let n = case.name;
        assert_eq!(result.as_ref().err().map(|e| e.status.name), case.error, "{n}");
        let phase = result.err().map_or(Phase::Done, |e| e.phase);
        assert_eq!(phase, if case.error.is_some() { Phase::Identity } else { Phase::Done }, "{n}");
        assert_eq!(seen.len(), 1, "{n}");
        let (id, check, authenticated_before) = &seen[0];
        assert_eq!((*check, *authenticated_before), (case.check, 0), "{n}");
        assert_eq!((id.kind, id.pin.as_str()), (IdentityKind::Ssh, pin_for(b"k1").as_str()), "{n}");
        // XC-16: filled in when the backend gave none.
        assert!(id.fingerprint.starts_with("SHA256:") && id.fingerprint.len() == 50, "{n}");
        assert_eq!(id.public_key, b"k1", "{n}");
        // C-7: a refusal sends nothing and disconnects.
        let ok = case.error.is_none();
        assert_eq!(
            (f.log_count("authenticate"), f.log_count("disconnect")),
            (i32::from(ok), i32::from(!ok)),
            "{n}"
        );
    }
    // No hook: an unknown identity fails before authenticate.
    f.reset();
    f.set_identity_pin(&pin_for(b"k1"));
    let mut conn = env.ffi.conn_new("fake").unwrap();
    let err = establish(&mut conn, "", &secret(b"secret")).unwrap_err();
    assert_eq!((err.phase, err.status.name), (Phase::Identity, ErrorName::ServerIdentityUnknown));
    assert_eq!((f.log_count("connect"), f.log_count("authenticate")), (1, 0));
}

type Answers = Vec<Vec<Zeroizing<Vec<u8>>>>;

fn establish_prompt_replies(env: &Env) {
    let f = env.fake;
    let otp = || Zeroizing::new(b"246810".to_vec());
    let old = || Zeroizing::new(b"old".to_vec());
    let cases: [(&str, Answers, bool, Option<ErrorName>, i32); 5] = [
        ("accepted", vec![vec![otp()]], true, None, 1),
        ("replaced, the last one counts", vec![vec![old()], vec![otp()]], true, None, 1),
        ("count mismatch declines", vec![vec![otp(), otp()]], true, Some(ErrorName::AuthFailed), 0),
        ("hook declines", vec![vec![otp()]], false, Some(ErrorName::AuthFailed), 0),
        ("no answers", vec![], true, Some(ErrorName::AuthFailed), 0),
    ];
    for (name, replies, answer, error, delivered) in cases {
        f.reset();
        f.set_otp(b"246810");
        let mut requests: Vec<PromptRequest> = Vec::new();
        let mut prompt = |request: &PromptRequest, reply: &mut Reply<'_>| {
            requests.push(request.clone());
            for set in &replies {
                reply.set(set);
            }
            answer
        };
        let mut hooks = EstablishHooks { identity: None, prompt: Some(&mut prompt) };
        let mut conn = env.ffi.conn_new("fake").unwrap();
        let result = conn.establish(&params(), "", &secret(b"secret"), &mut hooks);
        assert_eq!(result.as_ref().err().map(|e| e.status.name), error, "{name}");
        if let Err(e) = result {
            assert_eq!(e.phase, Phase::Authenticate, "{name}");
        }
        assert_eq!(requests.len(), 1, "{name}");
        assert_eq!(requests[0].name, "fake");
        assert_eq!(requests[0].prompts.len(), 1);
        assert_eq!(
            (requests[0].prompts[0].text.as_str(), requests[0].prompts[0].echo),
            ("Verification code: ", false)
        );
        assert_eq!(f.log_count("answers:"), delivered, "{name}");
    }
    // No prompt hook: no prompter, so the second factor fails.
    f.reset();
    f.set_otp(b"246810");
    let mut conn = env.ffi.conn_new("fake").unwrap();
    let err = establish(&mut conn, "", &secret(b"secret")).unwrap_err();
    assert_eq!((err.phase, err.status.name), (Phase::Authenticate, ErrorName::AuthFailed));
    assert_eq!(f.log_count("disconnect"), 1);
}

fn establish_phases(env: &Env) {
    let f = env.fake;
    // Connect fails: nothing to disconnect.
    f.fail_op("connect", ErrorName::NetworkUnreachable);
    let mut conn = env.ffi.conn_new("fake").unwrap();
    let err = establish(&mut conn, "", &secret(b"secret")).unwrap_err();
    assert_eq!((err.phase, err.status.name), (Phase::Connect, ErrorName::NetworkUnreachable));
    assert_eq!(f.log_count("disconnect"), 0);
    // Wrong secret.
    let mut conn = env.ffi.conn_new("fake").unwrap();
    let err = establish(&mut conn, "", &secret(b"wrong")).unwrap_err();
    assert_eq!((err.phase, err.status.name), (Phase::Authenticate, ErrorName::AuthFailed));
    assert_eq!(f.log_count("disconnect"), 1);
    // No secret.
    f.set_credentials("user", b"");
    let mut conn = env.ffi.conn_new("fake").unwrap();
    establish(&mut conn, "", &Secret::None { user: "user".into() }).unwrap();
    // A signond lookup cannot wait on the Qt thread (this one).
    let mut conn = env.ffi.conn_new("fake").unwrap();
    let signon = Secret::Signon { user: "user".into(), credentials_id: 0, secret_optional: true };
    let err = establish(&mut conn, "", &signon).unwrap_err();
    assert_eq!((err.phase, err.status.name), (Phase::Credentials, ErrorName::Internal));
}

fn establish_signon_off_qt_thread(env: &Env) {
    // XA-7: credentials id 0 with an optional secret: empty credentials
    // without signond; A-6: no stored secret is AuthFailed otherwise.
    let f = env.fake;
    for optional in [true, false] {
        f.reset();
        f.set_credentials("user", b"");
        let ffi = env.ffi;
        let (result, disconnects) = off_qt_thread(env, move || {
            let mut conn = ffi.conn_new("fake").unwrap();
            let signon = Secret::Signon { user: "user".into(), credentials_id: 0, secret_optional: optional };
            // Counted while the connection lives: conn_free disconnects too.
            (establish(&mut conn, "", &signon), f.log_count("disconnect"))
        });
        if optional {
            result.unwrap();
            assert_eq!(f.log_count("authenticate"), 1);
        } else {
            let err = result.unwrap_err();
            assert_eq!((err.phase, err.status.name), (Phase::Credentials, ErrorName::AuthFailed));
            assert_eq!((f.log_count("authenticate"), disconnects), (0, 1));
        }
    }
}

fn list_batches_and_stop(env: &Env) {
    let f = env.fake;
    for i in 0..10 {
        f.add_file(format!("/dir/f{i}").as_bytes(), b"x");
    }
    f.add_file(b"/dir/n\xff", b"");
    let mut conn = connected(env);
    let mut batches: Vec<Vec<Vec<u8>>> = Vec::new();
    conn.list(b"/dir", 3, |batch| {
        batches.push(names(batch));
        true
    })
    .unwrap();
    // One sink call per backend batch.
    assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [3, 3, 3, 2]);
    // XC-4: names cross as protocol bytes.
    assert_eq!(batches[3].last().unwrap(), b"n\xff");

    let mut calls = 0;
    let stopped = conn.list(b"/dir", 3, |_| {
        calls += 1;
        false
    });
    assert_eq!((name_of(&stopped), calls), (Some(ErrorName::Canceled), 1));
    assert_eq!(name_of(&conn.list(b"/nope", 3, |_| true)), Some(ErrorName::NotFound));
}

fn walk_visit_and_stop(env: &Env) {
    let f = env.fake;
    f.add_file(b"/t/a/one", b"1");
    f.add_file(b"/t/a/b/two", b"2");
    f.add_file(b"/t/three", b"3");
    let mut conn = connected(env);
    let walk = |conn: &mut Conn, options: WalkOptions, stop_after: usize| {
        let mut paths = Vec::new();
        let result = conn.walk(b"/t", &options, |path, entry| {
            let dir = if entry.kind == entry_kind::DIRECTORY { "/" } else { "" };
            paths.push(format!("{}{dir}", String::from_utf8_lossy(path)));
            paths.len() < stop_after
        });
        paths.sort();
        (result, paths)
    };
    let (result, all) = walk(&mut conn, WalkOptions::default(), usize::MAX);
    result.unwrap();
    assert_eq!(all, ["/t/a/", "/t/a/b/", "/t/a/b/two", "/t/a/one", "/t/three"]);
    let (result, top) =
        walk(&mut conn, WalkOptions { max_depth: Some(0), ..WalkOptions::default() }, usize::MAX);
    result.unwrap();
    assert_eq!(top, ["/t/a/", "/t/three"]);
    let (result, stopped) = walk(&mut conn, WalkOptions::default(), 2);
    assert_eq!((name_of(&result), stopped.len()), (Some(ErrorName::Canceled), 2));
}

fn remove_tree_counts(env: &Env) {
    let f = env.fake;
    f.add_file(b"/r/a/one", b"1");
    f.add_file(b"/r/a/two", b"2");
    f.add_file(b"/r/three", b"3");
    let mut conn = connected(env);
    let mut ticks = Ticks::default();
    let (counts, result) = conn.remove_tree(b"/r", Some(&mut ticks));
    result.unwrap();
    assert_eq!(counts, TreeCounts { files: 3, dirs: 2 });
    assert!(!f.exists(b"/r"));
    // Design §1.2: update(files + dirs, -1) per removed entry.
    assert_eq!(ticks.updates.len(), 5);
    assert_eq!(ticks.updates.last(), Some(&(5, -1)));

    f.add_file(b"/s/a", b"1");
    f.add_file(b"/s/b", b"2");
    let mut stopping = Ticks { cancel_after: Some(1), ..Ticks::default() };
    let (counts, result) = conn.remove_tree(b"/s", Some(&mut stopping));
    assert_eq!((name_of(&result), counts.files), (Some(ErrorName::Canceled), 1));
    assert!(f.exists(b"/s"));
    // Without progress.
    let (counts, result) = conn.remove_tree(b"/s", None);
    result.unwrap();
    assert_eq!(counts, TreeCounts { files: 1, dirs: 1 });
    let (counts, result) = conn.remove_tree(b"/s", None);
    assert_eq!((name_of(&result), counts), (Some(ErrorName::NotFound), TreeCounts::default()));
}

fn metadata_and_namespace(env: &Env) {
    let f = env.fake;
    f.add_file(b"/m/file", b"abc");
    let mut c = connected(env);
    let e = c.stat(b"/m/file", true).unwrap();
    assert_eq!(
        (e.name.as_slice(), e.kind, e.size, e.mode, e.uid),
        (&b"file"[..], entry_kind::FILE, 3, 0o644, -1)
    );
    assert!(e.mtime_ms > 0);

    c.make_dir(b"/m/d", true).unwrap();
    assert_eq!(name_of(&c.make_dir(b"/m/d", true)), Some(ErrorName::AlreadyExists));
    c.make_dir(b"/m/d", false).unwrap();
    c.rename(b"/m/file", b"/m/d/moved", false).unwrap();
    assert!(f.exists(b"/m/d/moved"));
    c.make_symlink(b"d/moved", b"/m/link").unwrap();
    assert_eq!(c.read_link(b"/m/link").unwrap(), b"d/moved");
    assert_eq!(c.stat(b"/m/link", false).unwrap().kind, entry_kind::SYMLINK);
    assert_eq!(c.stat(b"/m/link", true).unwrap().kind, entry_kind::FILE);
    c.make_hardlink(b"/m/d/moved", b"/m/hard").unwrap();
    c.copy(b"/m/d", b"/m/copy", true, false).unwrap();
    assert!(f.exists(b"/m/copy/moved"));
    assert_eq!(name_of(&c.copy(b"/m/d", b"/m/copy", true, false)), Some(ErrorName::AlreadyExists));
    c.copy(b"/m/hard", b"/m/copy/moved", false, true).unwrap();
    assert_eq!(name_of(&c.rename(b"/m/hard", b"/m/copy/moved", false)), Some(ErrorName::AlreadyExists));
    c.set_attributes(b"/m/hard", &Attributes { mode: Some(0o600), mtime_ms: Some(1000), atime_ms: None })
        .unwrap();
    assert_eq!(f.node_mode(b"/m/hard"), Some(0o600));
    assert_eq!(f.node_mode(b"/m/none"), None);
    assert_eq!(c.stat(b"/m/hard", true).unwrap().mtime_ms, 1000);

    // sha256("abc")
    let digest = c.checksum(b"/m/hard", "sha256").unwrap();
    assert_eq!(digest[..4], [0xba, 0x78, 0x16, 0xbf]);
    assert_eq!(digest.len(), 32);
    let space = c.space_info(b"/m").unwrap();
    assert_eq!(space.free_bytes, 1 << 40);
    let caps = c.capabilities().unwrap();
    assert!(caps.flags.iter().any(|f| f == "Symlinks"));
    assert_eq!((caps.checksum_algorithms.len(), caps.max_name_bytes), (2, 255));

    c.remove_file(b"/m/hard").unwrap();
    assert_eq!(name_of(&c.remove_dir(b"/m/d")), Some(ErrorName::DirectoryNotEmpty));
    c.remove_file(b"/m/d/moved").unwrap();
    c.remove_dir(b"/m/d").unwrap();
    assert!(!f.exists(b"/m/d"));
    assert_eq!(name_of(&c.remove_file(b"/m/d")), Some(ErrorName::NotFound));
    assert_eq!(name_of(&c.read_link(b"/m/none")), Some(ErrorName::NotFound));
    assert_eq!(name_of(&c.checksum(b"/m/none", "sha256")), Some(ErrorName::NotFound));
    assert_eq!(name_of(&c.stat(b"/m/none", true)), Some(ErrorName::NotFound));
    f.fail_op("spaceInfo", ErrorName::Unsupported);
    assert_eq!(name_of(&c.space_info(b"/m")), Some(ErrorName::Unsupported));
    c.reset_cancel().unwrap();
}

fn handles_read_eof(env: &Env) {
    let f = env.fake;
    f.add_file(b"/h", b"0123456789");
    let mut conn = connected(env);
    let (mut h, size) = conn.open_read(b"/h").unwrap();
    assert_eq!(size, 10);
    let mut buf = [0u8; 8];
    assert_eq!(h.read(2, &mut buf[..4]).unwrap(), 4);
    assert_eq!(&buf[..4], b"2345");
    // XC-13: short only at EOF; at or past EOF nothing.
    assert_eq!(h.read(7, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"789");
    assert_eq!(h.read(40, &mut buf).unwrap(), 0);
    h.read_ahead(0, 10);
    assert!(format!("{h:?}").starts_with("Handle"));
    h.close().unwrap();
    assert_eq!(f.log_count("close:h"), 1);
    assert_eq!(name_of(&conn.open_read(b"/nope")), Some(ErrorName::NotFound));
    // Dropping a handle closes it; the connection stays.
    let (h, _) = conn.open_read(b"/h").unwrap();
    drop(h);
    assert_eq!((f.log_count("close:h"), f.log_count("disconnect")), (2, 0));
    // A read error.
    let (mut h, _) = conn.open_read(b"/h").unwrap();
    f.fail_op("read", ErrorName::ConnectionLost);
    assert_eq!(name_of(&h.read(0, &mut buf)), Some(ErrorName::ConnectionLost));
    // A close error: a failed establish disconnected the handle's backend.
    assert!(establish(&mut conn, "", &secret(b"wrong")).is_err());
    assert_eq!(f.log_count("disconnect"), 1);
    assert_eq!(name_of(&h.close()), Some(ErrorName::ConnectionLost));
}

fn upload_download_via_io(env: &Env) {
    let f = env.fake;
    let mut conn = connected(env);
    let data = pattern(200_000);
    let size = i64::try_from(data.len()).unwrap();

    let mut source = Memory { data: data.clone(), ..Memory::default() };
    let options = UploadOptions::CreateNew { mode: None, expected_size: Some(size), mtime_ms: Some(5000) };
    let mut ticks = Ticks::default();
    conn.upload(b"/up", &options, &mut source, (false, size), Some(&mut ticks)).unwrap();
    assert_eq!(f.file_data(b"/up").unwrap(), data);
    assert_eq!(f.file_data(b"/none"), None);
    assert_eq!(ticks.updates.last().map(|u| u.0), Some(size));
    assert_eq!(conn.stat(b"/up", true).unwrap().mtime_ms, 5000);
    // CreateNew refuses an existing file.
    let mut again = Memory { data: data.clone(), ..Memory::default() };
    let refused = conn.upload(b"/up", &options, &mut again, (false, size), None);
    assert_eq!(name_of(&refused), Some(ErrorName::AlreadyExists));

    // Short writes into a regular file are retried until all is written.
    let mut sink = Memory { max_write: Some(1000), ..Memory::default() };
    conn.download(b"/up", (100, 70_000), &mut sink, (false, 0), None).unwrap();
    assert_eq!(sink.data, data[100..70_100]);
    assert!(sink.writes >= 70);

    // A failing write (-1) is an error.
    let mut failing = Memory { fail_writes: true, ..Memory::default() };
    assert!(conn.download(b"/up", (0, -1), &mut failing, (false, 0), None).is_err());
    assert!(failing.writes >= 1);

    // canceled() stops the transfer.
    let mut source = Memory { data, ..Memory::default() };
    let mut stopping = Ticks { cancel_after: Some(1), ..Ticks::default() };
    let truncate = UploadOptions::Truncate { expected_size: None, mtime_ms: None };
    let stopped = conn.upload(b"/up", &truncate, &mut source, (false, size), Some(&mut stopping));
    assert_eq!(name_of(&stopped), Some(ErrorName::Canceled));

    // Resume appends at the offset; a FIFO is read sequentially.
    let mut tail = Memory { data: b"tail".to_vec(), ..Memory::default() };
    let resume = UploadOptions::Resume { offset: 3, expected_size: None, mtime_ms: None };
    f.add_file(b"/r", b"abc");
    conn.upload(b"/r", &resume, &mut tail, (true, 0), None).unwrap();
    assert_eq!(f.file_data(b"/r").unwrap(), b"abctail");
    let mut fifo = Memory::default();
    conn.download(b"/r", (0, -1), &mut fifo, (true, 0), None).unwrap();
    assert_eq!(fifo.data, b"abctail");
}

fn cancel_from_other_thread_during_list(env: &Env) {
    let f = env.fake;
    for i in 0..40 {
        f.add_file(format!("/slow/f{i}").as_bytes(), b"x");
    }
    let mut conn = connected(env);
    f.set_chunk_delay_ms(100);
    let started = AtomicBool::new(false);
    let canceled_at: Mutex<Option<Instant>> = Mutex::new(None);
    let cancel = conn.cancel_handle();
    let mut batches = 0;
    let (result, elapsed) = thread::scope(|s| {
        s.spawn(|| {
            while !started.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(5));
            }
            thread::sleep(Duration::from_millis(200));
            *canceled_at.lock().unwrap() = Some(Instant::now());
            assert!(cancel.cancel());
        });
        let result = conn.list(b"/slow", 1, |_| {
            started.store(true, Ordering::SeqCst);
            batches += 1;
            true
        });
        (result, canceled_at.lock().unwrap().map(|t| t.elapsed()))
    });
    assert_eq!(name_of(&result), Some(ErrorName::Canceled));
    // C-9: within 2 s of the cancel.
    let elapsed = elapsed.unwrap();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert!(batches < 40);
    // Usable again after reset_cancel.
    conn.reset_cancel().unwrap();
    f.set_chunk_delay_ms(0);
    let mut after = 0;
    conn.list(b"/slow", 64, |_| {
        after += 1;
        true
    })
    .unwrap();
    assert_eq!(after, 1);
}

fn copy_across_two_conns(env: &Env) {
    let f = env.fake;
    let data = pattern(300_000);
    f.add_file(b"/src/big", &data);
    f.add_file(b"/src/tree/a", b"a");
    f.add_dir(b"/dst", None);
    assert_eq!(f.node_mode(b"/dst"), Some(0o755));
    f.add_dir(b"/dst/private", Some(0o700));
    assert_eq!(f.node_mode(b"/dst/private"), Some(0o700));
    f.add_symlink(b"/src/link", b"big");
    let mut source = connected(env);
    let mut destination = connected(env);
    let mut ticks = Ticks::default();
    source.copy_across(b"/src/big", &mut destination, b"/dst/big", (false, false), Some(&mut ticks)).unwrap();
    assert_eq!(f.file_data(b"/dst/big").unwrap(), data);
    assert!(!ticks.updates.is_empty());
    let again = source.copy_across(b"/src/big", &mut destination, b"/dst/big", (false, false), None);
    assert_eq!(name_of(&again), Some(ErrorName::AlreadyExists));
    source.copy_across(b"/src/big", &mut destination, b"/dst/big", (false, true), None).unwrap();
    source.copy_across(b"/src/tree", &mut destination, b"/dst/tree", (true, false), None).unwrap();
    assert!(f.exists(b"/dst/tree/a"));
    assert_eq!(source.read_link(b"/src/link").unwrap(), b"big");
}

fn url_parse_format(env: &Env) {
    let ffi = env.ffi;
    let url = ffi.url_parse("sftp://alice@host.example:2222/home/a%FFb").unwrap();
    let p = &url.params;
    assert_eq!(
        (p.provider.as_str(), p.host.as_str(), p.port, p.username.as_str()),
        ("sftp", "host.example", 2222, "alice")
    );
    assert_eq!(url.path, b"/home/a\xffb");
    assert_eq!(p.connect_timeout_ms, 15000);
    assert_eq!(ffi.url_format(&url.params, &url.path).unwrap(), "sftp://alice@host.example:2222/home/a%FFb");
    // XH-6: a password is refused; IDN; smb share and file://.
    assert_eq!(name_of(&ffi.url_parse("sftp://alice:pw@host/")), Some(ErrorName::SecurityPolicy));
    assert_eq!(ffi.url_parse("sftp://xn--bcher-kva.de/x").unwrap().params.host, "bücher.de");
    let smb = ffi.url_parse("smb://nas/share/dir").unwrap();
    assert_eq!(smb.params.options.get("share"), Some(&Value::Str("share".into())));
    assert_eq!(smb.path, b"/dir");
    assert_eq!(ffi.url_format(&smb.params, &smb.path).unwrap(), "smb://nas/share/dir");
    assert_eq!(ffi.url_parse("file:///tmp/x").unwrap().params.provider, "local");
    assert_eq!(name_of(&ffi.url_parse("gopher://h/")), Some(ErrorName::Unsupported));
    let dav = ffi.url_parse("davs://dav.example/remote.php/files").unwrap();
    assert_eq!(dav.params.options.get("base_path"), Some(&Value::Str("/remote.php/files".into())));
    let unknown = Params { provider: "fake".into(), ..Params::default() };
    assert_eq!(name_of(&ffi.url_format(&unknown, b"/")), Some(ErrorName::Unsupported));
    // Options of every kind reach C++ (an unknown one is not carried).
    let mut typed = smb.params.clone();
    typed.options.insert("x-int".into(), Value::Int(3));
    typed.options.insert("x-bool".into(), Value::Bool(true));
    typed.options.insert("x-bytes".into(), Value::Bytes(vec![1]));
    typed.options.insert("x-list".into(), Value::StrList(vec!["a".into()]));
    assert_eq!(ffi.url_format(&typed, &smb.path).unwrap(), "smb://nas/share/dir");
}

fn error_mapping(env: &Env) {
    let f = env.fake;
    let mut conn = connected(env);
    f.add_file(b"/x", b"x");
    for name in ErrorName::ALL {
        f.fail_op("stat", name);
        let status = conn.stat(b"/x", true).unwrap_err();
        let expected =
            Status { name, message: format!("Injected {name}"), detail: String::new(), retry_after_ms: -1 };
        assert_eq!(status, expected);
    }
    conn.stat(b"/x", true).unwrap();
    // The phase travels with an establish failure.
    f.fail_op("authenticate", ErrorName::Locked);
    let mut fresh = env.ffi.conn_new("fake").unwrap();
    let err = establish(&mut fresh, "", &secret(b"secret")).unwrap_err();
    assert_eq!(
        (err.phase, err.status.name, err.status.message.as_str()),
        (Phase::Authenticate, ErrorName::Locked, "Injected Locked")
    );
}

fn post_and_quit(env: &Env) {
    let ffi = env.ffi;
    // From another thread while the loop runs: on the Qt thread, and its
    // quit() ends run() with the code.
    let ran = Arc::new(AtomicUsize::new(0));
    let on_qt = Arc::new(AtomicBool::new(false));
    let poster = {
        let (ran, on_qt) = (Arc::clone(&ran), Arc::clone(&on_qt));
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            ffi.post(move || {
                on_qt.store(ffi.on_qt_thread(), Ordering::SeqCst);
                ran.fetch_add(1, Ordering::SeqCst);
                ffi.quit(7);
            })
        })
    };
    assert_eq!(ffi.run(), Ok(7));
    assert!(poster.join().unwrap());
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert!(on_qt.load(Ordering::SeqCst));

    // Quitting: not queued, never runs, and the function is dropped.
    let late = Arc::new(AtomicUsize::new(0));
    let held = Arc::clone(&late);
    assert!(!ffi.post(move || {
        held.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!((Arc::strong_count(&late), late.load(Ordering::SeqCst)), (1, 0));

    // A quit() before run() still ends the next run().
    ffi.quit(5);
    assert_eq!(ffi.run(), Ok(5));
}

fn callback_panics_do_not_unwind(env: &Env) {
    let f = env.fake;
    f.add_file(b"/p/a", b"a");
    f.add_file(b"/p/b", b"b");
    let mut conn = connected(env);
    let panicked = |r: &Result<(), Status>, text: &str| {
        let s = r.as_ref().unwrap_err();
        assert_eq!(
            (s.name, s.message.as_str()),
            (ErrorName::Internal, format!("callback panicked: {text}").as_str())
        );
    };
    // List sink: stops (0) and is not called again.
    let mut calls = 0;
    let r = conn.list(b"/p", 1, |_| {
        calls += 1;
        panic!("sink broke")
    });
    panicked(&r, "sink broke");
    assert_eq!(calls, 1);
    // Walk visitor.
    let r = conn.walk(b"/p", &WalkOptions::default(), |_, _| panic!("visit broke"));
    panicked(&r, "visit broke");
    // Progress (update panics; canceled() then stops).
    let mut ticks = Ticks { panic: true, ..Ticks::default() };
    let (_, r) = conn.remove_tree(b"/p", Some(&mut ticks));
    panicked(&r, "progress broke");
    // nvb_io read: -1.
    let mut source = Memory { data: b"data".to_vec(), panic_on_read: true, ..Memory::default() };
    let options = UploadOptions::Truncate { expected_size: None, mtime_ms: None };
    let r = conn.upload(b"/p/up", &options, &mut source, (false, 4), None);
    panicked(&r, "read broke");
    // The connection still works.
    assert_eq!(conn.stat(b"/p", true).unwrap().kind, entry_kind::DIRECTORY);

    // Identity hook: cancels, nothing is sent.
    f.reset();
    f.set_identity_pin(&pin_for(b"k1"));
    let mut identity = |_: &Identity, _: Option<&Status>| -> Verdict { panic!("identity broke") };
    let mut hooks = EstablishHooks { identity: Some(&mut identity), prompt: None };
    let mut fresh = env.ffi.conn_new("fake").unwrap();
    let err = fresh.establish(&params(), "", &secret(b"secret"), &mut hooks).unwrap_err();
    assert_eq!(
        (err.phase, err.status.message.as_str()),
        (Phase::Identity, "callback panicked: identity broke")
    );
    assert_eq!(f.log_count("authenticate"), 0);
    // Prompt hook: declines.
    f.reset();
    f.set_otp(b"1");
    let mut prompt = |_: &PromptRequest, _: &mut Reply<'_>| -> bool { panic!("prompt broke") };
    let mut hooks = EstablishHooks { identity: None, prompt: Some(&mut prompt) };
    let mut fresh = env.ffi.conn_new("fake").unwrap();
    let err = fresh.establish(&params(), "", &secret(b"secret"), &mut hooks).unwrap_err();
    assert_eq!(
        (err.phase, err.status.message.as_str()),
        (Phase::Authenticate, "callback panicked: prompt broke")
    );
    assert_eq!(f.log_count("answers:"), 0);

    // A posted function: kept for take_orphan_panics.
    drop(take_orphan_panics());
    let ffi = env.ffi;
    off_qt_thread(env, move || {
        let (tx, rx) = mpsc::channel();
        assert!(ffi.post(|| panic!("posted broke")));
        assert!(ffi.post(move || tx.send(()).unwrap()));
        rx.recv().unwrap();
    });
    assert_eq!(take_orphan_panics(), ["posted broke"]);
}

fn calls_from_callbacks_refused(env: &Env) {
    // T6: inside a callback only conn_cancel, reply_set and free.
    let f = env.fake;
    f.add_file(b"/c/a", b"a");
    let mut conn = connected(env);
    let mut other = connected(env);
    let cancel = conn.cancel_handle();
    let ffi = env.ffi;
    let mut refused = Vec::new();
    let r = conn.list(b"/c", 8, |_| {
        refused.push(name_of(&other.stat(b"/c/a", true)));
        refused.push(name_of(&ffi.conn_new("fake")));
        refused.push(name_of(&other.reset_cancel()));
        assert!(cancel.cancel());
        true
    });
    assert_eq!(refused, [Some(ErrorName::Internal); 3]);
    // The cancel from inside counts: the listing ends Canceled or done.
    assert!(r.is_ok() || name_of(&r) == Some(ErrorName::Canceled));
    conn.reset_cancel().unwrap();
    other.stat(b"/c/a", true).unwrap();
}

fn discovery_start_stop(env: &Env) {
    // T3: only on the Qt thread.
    let ffi = env.ffi;
    let off = thread::spawn(move || Discovery::new(ffi, |_| {}).map(|_| ())).join().unwrap();
    assert_eq!(name_of(&off), Some(ErrorName::Internal));
    // On it, inside a posted function. Sockets may be unavailable in a
    // sandbox, so only the bookkeeping is checked.
    let (opened, free_calls) = off_qt_thread(env, move || {
        let (tx, rx) = mpsc::channel();
        assert!(ffi.post(move || {
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&calls);
            let mut d = Discovery::new(ffi, move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
            assert!(format!("{d:?}").starts_with("Discovery"));
            let open = d.set_running(true);
            assert_eq!(d.set_running(true), open);
            assert!(!d.set_running(false));
            assert!(!d.set_running(false));
            assert_eq!(d.set_running(true), open);
            assert_eq!(d.take_panic(), None);
            drop(d);
            // Dropping frees the C++ discovery and the hook's context.
            let grown = heap_growth(|| drop(Discovery::new(ffi, |_| {}).unwrap())).unwrap_or(0);
            assert!(grown < LEAK_LIMIT, "{grown} bytes more in use after dropping discoveries");
            tx.send((open, calls.load(Ordering::SeqCst))).unwrap();
        }));
        rx.recv().unwrap()
    });
    // Whatever was reported, nothing panicked and nothing is left behind.
    println!("discovery socket open: {opened}, reports: {free_calls}");
    assert!(take_orphan_panics().is_empty());
}

/// Heap growth allowed over [`ROUNDS`] calls: far below one leaked block
/// per call.
const LEAK_LIMIT: usize = 256 * 1024;
const ROUNDS: usize = 4000;

/// Bytes `malloc` has handed out and not taken back, in all arenas.
/// `None` under ASan, whose allocator glibc's counters do not see (LSan
/// finds leaks there).
#[allow(unsafe_code)]
fn heap_in_use() -> Option<usize> {
    // SAFETY: dlsym takes RTLD_DEFAULT and a C string; mallinfo2 has no
    // preconditions.
    unsafe {
        let asan = !libc::dlsym(libc::RTLD_DEFAULT, c"__asan_init".as_ptr()).is_null();
        (!asan).then(|| libc::mallinfo2().uordblks)
    }
}

/// Bytes more in use after `ROUNDS` calls of `f` than before, after a
/// warm-up (caches, arenas, Qt's one-time allocations); `None` when the
/// heap cannot be measured. The measure is checked to see a block first.
fn heap_growth(mut f: impl FnMut()) -> Option<usize> {
    let before = heap_in_use()?;
    let probe = std::hint::black_box(vec![1u8; 64 * 1024]);
    assert!(heap_in_use()? >= before + probe.len(), "the heap measure does not see a block");
    drop(probe);
    (0..ROUNDS / 10).for_each(|_| f());
    let before = heap_in_use()?;
    (0..ROUNDS).for_each(|_| f());
    Some(heap_in_use()?.saturating_sub(before))
}

fn results_are_freed(env: &Env) {
    // O3: every block a call returns is freed once read.
    let ffi = env.ffi;
    let grown = heap_growth(|| {
        let url = ffi.url_parse("sftp://alice@host.example:2222/home/a%FFb").unwrap();
        assert_eq!(
            ffi.url_format(&url.params, &url.path).unwrap(),
            "sftp://alice@host.example:2222/home/a%FFb"
        );
        assert_eq!(name_of(&ffi.url_parse("sftp://alice:pw@host/")), Some(ErrorName::SecurityPolicy));
    })
    .unwrap_or(0);
    assert!(grown < LEAK_LIMIT, "{grown} bytes more in use after {ROUNDS} rounds");
}
