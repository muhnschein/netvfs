// SPDX-License-Identifier: LGPL-2.1-or-later
//! Workers, pools, connector, copy jobs and job bodies against the real `libnetvfs-bridge-ffi.so` with the fake backend (variables of `tests/ffi.rs`; without them every test says it is skipped and passes).
//!
//! Own harness as `tests/ffi.rs`: `init` and the Qt event loop run on the main thread, each test on a thread of its own (workers block, the main thread serves signond).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::assertions_on_result_states
)]

use netvfs_bridge::Status;
use netvfs_bridge::ffi::fake::{self, Fake};
use netvfs_bridge::ffi::{Conn, Ffi, Handle, Params, Value};
use netvfs_bridge::jobs::fd::{FdAccess, FdInfo, check_transfer_fd};
use netvfs_bridge::jobs::{batch, remove, transfer, walk};
use netvfs_bridge::locations::book::LocationBook;
use netvfs_bridge::locations::connector::{
    AccountAccess, Connector, IDENTITY_UNKNOWN, KEYBOARD_INTERACTIVE, PinStore,
};
use netvfs_bridge::locations::copyjobs::{CopyId, CopyJobs};
use netvfs_bridge::locations::pool::{CONNECTION_IDLE, PoolSet};
use netvfs_bridge::locations::spec::{AdHocSecret, Attention, LocationSpec};
use netvfs_bridge::locations::worker::{Handles, Turn, WorkerId};
use netvfs_bridge::locations::{Answer, AskId, TaskContext, WorkerEvent, WorkerEvents};
use netvfs_bridge::server::FlowBudget;
use netvfs_bridge::server::SessionId;
use netvfs_bridge::server::args::{Disposition, TransferOpts, WalkOpts};
use netvfs_bridge_proto::{ErrorName, Lane, WireEntry, WireWalkItem};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use zbus::zvariant::OwnedValue;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
struct Env {
    ffi: Ffi,
    fake: Fake,
}

type Test = fn(&Env);

const TESTS: &[(&str, Test)] = &[
    ("account_connects_with_its_pin_and_signon", account_connects_with_its_pin_and_signon),
    ("account_identity_problems_set_attention", account_identity_problems_set_attention),
    ("account_auth_failure_sets_attention", account_auth_failure_sets_attention),
    ("account_data_failures", account_data_failures),
    ("ad_hoc_identity_question", ad_hoc_identity_question),
    ("ad_hoc_secret_and_forget", ad_hoc_secret_and_forget),
    ("keyboard_interactive_question", keyboard_interactive_question),
    ("connections_are_reused_and_dropped", connections_are_reused_and_dropped),
    ("cancel_kicks_a_running_listing", cancel_kicks_a_running_listing),
    ("list_streams_batches", list_streams_batches),
    ("walk_and_remove_tree", walk_and_remove_tree),
    ("read_handles_live_on_their_worker", read_handles_live_on_their_worker),
    ("transfers_of_regular_files", transfers_of_regular_files),
    ("transfers_through_pipes", transfers_through_pipes),
    ("copy_jobs_use_two_connections", copy_jobs_use_two_connections),
];

const HANG: Duration = Duration::from_secs(30);

const VARIABLES: [&str; 3] = ["NETVFS_BRIDGE_FFI", fake::PATH_ENV, "NETVFS_BACKEND_PATH"];

impl Env {
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
    env.ffi.init("netvfs-bridge-backend-test").unwrap();
    let mut failed = 0;
    for (name, test) in tests {
        env.fake.reset();
        let watchdog = watch(name);
        let ok = off_qt_thread(&env, move |env| catch_unwind(AssertUnwindSafe(|| test(env))).is_ok());
        drop(watchdog);
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        failed += usize::from(!ok);
    }
    env.ffi.shutdown().unwrap();
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

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

struct QuitOnDrop(Ffi);

impl Drop for QuitOnDrop {
    fn drop(&mut self) {
        self.0.quit(0);
    }
}

fn wait_for_loop(ffi: Ffi) {
    let (tx, rx) = mpsc::channel();
    loop {
        let tx = tx.clone();
        if ffi.post(move || tx.send(()).unwrap()) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    rx.recv().unwrap();
}

/// Runs `work` on another thread while this one runs the Qt event loop.
fn off_qt_thread<R: Send>(env: &Env, work: impl FnOnce(&Env) -> R + Send) -> R {
    let env = *env;
    thread::scope(|s| {
        let worker = s.spawn(move || {
            let _quit = QuitOnDrop(env.ffi);
            wait_for_loop(env.ffi);
            work(&env)
        });
        assert_eq!(env.ffi.run(), Ok(0));
        worker.join().unwrap()
    })
}

/// What the core saw from workers.
#[derive(Debug)]
enum Seen {
    Ask { kind: &'static str, details: HashMap<String, OwnedValue> },
    Withdrawn(#[allow(dead_code)] AskId),
    Fetch(i32),
    Attention(i32, Attention, String),
    CopyDone(CopyId, Result<(), Status>),
    Warning(String),
}

/// Stand-in for the core: answers account fetches and questions from queues and records everything.
#[derive(Default)]
struct Core {
    access: Mutex<Option<Result<AccountAccess, Status>>>,
    answers: Mutex<VecDeque<Option<Answer>>>,
    /// Questions and fetches left unanswered (the senders stay alive).
    held: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
    seen: Mutex<Vec<Seen>>,
}

impl Core {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn events(self: &Arc<Self>) -> WorkerEvents {
        let core = Arc::clone(self);
        WorkerEvents::new(move |event| core.handle(event))
    }

    fn handle(&self, event: WorkerEvent) {
        let seen = match event {
            WorkerEvent::Ask { ask: _, session: _, kind, details, answer } => {
                let next = self.answers.lock().unwrap().pop_front();
                match next {
                    Some(reply) => drop(answer.send(reply)),
                    None => self.held.lock().unwrap().push(Box::new(answer)),
                }
                Seen::Ask { kind, details }
            }
            WorkerEvent::CancelQuestion(id) => Seen::Withdrawn(id),
            WorkerEvent::FetchAccount { account_id, reply } => {
                let access = self.access.lock().unwrap().clone();
                match access {
                    Some(access) => drop(reply.send(access)),
                    None => self.held.lock().unwrap().push(Box::new(reply)),
                }
                Seen::Fetch(account_id)
            }
            WorkerEvent::Attention { account_id, attention, pin } => {
                Seen::Attention(account_id, attention, pin)
            }
            WorkerEvent::CopyDone { id, result } => Seen::CopyDone(id, result),
            WorkerEvent::Warning(text) => Seen::Warning(text),
        };
        self.seen.lock().unwrap().push(seen);
    }

    fn give(&self, access: Option<Result<AccountAccess, Status>>) {
        *self.access.lock().unwrap() = access;
    }

    fn answer(&self, reply: Option<Answer>) {
        self.answers.lock().unwrap().push_back(reply);
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }

    fn asks(&self) -> Vec<(&'static str, HashMap<String, OwnedValue>)> {
        let mut seen = self.seen.lock().unwrap();
        let mut asks = Vec::new();
        let mut rest = Vec::new();
        for s in std::mem::take(&mut *seen) {
            match s {
                Seen::Ask { kind, details } => asks.push((kind, details)),
                other => rest.push(other),
            }
        }
        *seen = rest;
        drop(seen);
        asks
    }
}

/// Known pins in memory.
#[derive(Default)]
struct Pins {
    map: Mutex<BTreeMap<String, String>>,
    read_only: AtomicBool,
}

impl PinStore for Pins {
    fn pin(&self, key: &str) -> String {
        self.map.lock().unwrap().get(key).cloned().unwrap_or_default()
    }

    fn set_pin(&self, key: &str, pin: &str) -> bool {
        if self.read_only.load(Ordering::Acquire) {
            return false;
        }
        self.map.lock().unwrap().insert(key.to_owned(), pin.to_owned());
        true
    }

    fn remove(&self, key: &str) -> bool {
        self.map.lock().unwrap().remove(key).is_some()
    }
}

struct Rig {
    core: Arc<Core>,
    pins: Arc<Pins>,
    book: LocationBook<Connector>,
}

fn rig(env: &Env) -> Rig {
    rig_with(env, Duration::from_secs(10), Duration::from_secs(10))
}

fn rig_with(env: &Env, questions: Duration, fetch: Duration) -> Rig {
    let core = Core::new();
    let pins = Arc::new(Pins::default());
    let pin_store: Arc<dyn PinStore> = Arc::<Pins>::clone(&pins);
    let connector = Connector::new(env.ffi, pin_store, core.events(), questions).with_fetch_timeout(fetch);
    let book = LocationBook::new(PoolSet::new(Arc::new(connector), 4));
    Rig { core, pins, book }
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

/// Account 7 at fake.example, its data with `host_key` (if any) and an optional secret (credentials id 0).
fn account(rig: &mut Rig, host_key: Option<&str>) -> String {
    let spec = LocationSpec::account(7, "fake", "Seven", params(), b"/".to_vec(), Attention::None);
    rig.book.set_accounts(vec![spec]);
    let mut access_params = params();
    if let Some(pin) = host_key {
        access_params.options.insert("host_key".into(), Value::Str(pin.into()));
    }
    rig.core.give(Some(Ok(AccountAccess {
        params: access_params,
        credentials_id: 0,
        secret_optional: true,
    })));
    assert!(rig.book.ensure_pool("account:7", true, |p| p == "fake").is_ok());
    "account:7".to_owned()
}

/// An ad-hoc location at fake.example with `user` / `secret`.
fn ad_hoc(rig: &mut Rig, secret: Option<&[u8]>) -> String {
    let id = rig.book.reserve_ad_hoc_id();
    let secret = secret.map(|s| AdHocSecret::new("user", Zeroizing::new(s.to_vec())));
    let spec = LocationSpec::ad_hoc(&id, "fake.example", params(), b"/".to_vec(), secret);
    assert!(rig.book.start_ad_hoc(spec));
    id
}

type Body<R> = Box<dyn FnOnce(&mut Conn, &mut Handles<Handle>, WorkerId) -> (R, Result<(), Status>) + Send>;

/// Runs `body` on a connection of `loc`; what it gave, or why there was no connection.
fn on_worker<R: Send + 'static>(
    rig: &mut Rig,
    loc: &str,
    task: TaskContext,
    body: Body<R>,
) -> mpsc::Receiver<Result<R, Status>> {
    let (tx, rx) = mpsc::channel();
    rig.book.submit(loc, Lane::Interactive, task, wrap(tx, body));
    rx
}

fn wrap<R: Send + 'static>(
    tx: mpsc::Sender<Result<R, Status>>,
    body: Body<R>,
) -> netvfs_bridge::locations::worker::Work<Connector> {
    Box::new(move |turn: Turn<'_, Connector>| match turn.ready {
        Ok(conn) => {
            let (value, result) = body(conn, turn.handles.unwrap(), turn.worker.unwrap());
            tx.send(Ok(value)).unwrap();
            result
        }
        Err(status) => {
            tx.send(Err(status.clone())).unwrap();
            Err(status)
        }
    })
}

/// Waits as the core does, with its maintenance tick: that reaps stopped connections whose threads finished, so work waiting for their host slots gets one.
#[track_caller]
fn get<R>(rig: &mut Rig, rx: &mpsc::Receiver<Result<R, Status>>) -> Result<R, Status> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {
                rig.book.maintain(Instant::now(), CONNECTION_IDLE);
            }
            Err(e) => panic!("the work did not run: {e}; {:?}", rig.book),
        }
    }
}

/// Establishes a connection of `loc` (an empty item, as `connectAdHoc`).
#[track_caller]
fn connect(rig: &mut Rig, loc: &str) -> Result<(), Status> {
    let rx = on_worker(rig, loc, TaskContext::detached(), Box::new(|_, _, _| ((), Ok(()))));
    get(rig, &rx)
}

fn name_of<T>(r: &Result<T, Status>) -> Option<ErrorName> {
    r.as_ref().err().map(|s| s.name)
}

fn text(v: &OwnedValue) -> String {
    String::try_from(v.try_clone().unwrap()).unwrap()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn account_connects_with_its_pin_and_signon(env: &Env) {
    let f = env.fake;
    f.set_identity_pin(&pin_for(b"k1"));
    f.set_credentials("user", b"");
    let mut rig = rig(env);
    let loc = account(&mut rig, Some(&pin_for(b"k1")));
    connect(&mut rig, &loc).unwrap();
    let seen = rig.core.take();
    assert!(matches!(seen.as_slice(), [Seen::Fetch(7)]), "{seen:?}");
    assert_eq!((f.log_count("connect"), f.log_count("authenticate")), (1, 1));
    assert!(rig.pins.map.lock().unwrap().is_empty());
    rig.book.disconnect(&loc);
    rig.core.give(Some(Err(Status::new(ErrorName::NotFound, "No such account"))));
    let failed = connect(&mut rig, &loc);
    assert_eq!(failed.unwrap_err().message, "No such account");
}

fn account_identity_problems_set_attention(env: &Env) {
    let f = env.fake;
    f.set_identity_pin(&pin_for(b"k1"));
    f.set_credentials("user", b"");
    for (pin, error) in
        [(Some(pin_for(b"k2")), ErrorName::ServerIdentityChanged), (None, ErrorName::ServerIdentityUnknown)]
    {
        let mut rig = rig(env);
        let loc = account(&mut rig, pin.as_deref());
        let failed = connect(&mut rig, &loc);
        assert_eq!(name_of(&failed), Some(error));
        let seen = rig.core.take();
        match seen.as_slice() {
            [Seen::Fetch(7), Seen::Attention(7, Attention::ServerIdentityChanged, seen_pin)] => {
                assert_eq!(*seen_pin, pin_for(b"k1"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(f.log_count("authenticate"), 0);
    }
}

fn account_auth_failure_sets_attention(env: &Env) {
    let f = env.fake;
    f.set_credentials("user", b"secret");
    let mut rig = rig(env);
    let loc = account(&mut rig, None);
    let failed = connect(&mut rig, &loc);
    assert_eq!(name_of(&failed), Some(ErrorName::AuthFailed));
    let seen = rig.core.take();
    assert!(
        matches!(seen.as_slice(), [Seen::Fetch(7), Seen::Attention(7, Attention::AuthFailed, pin)] if pin.is_empty()),
        "{seen:?}"
    );
    f.fail_op("connect", ErrorName::NetworkUnreachable);
    let failed = connect(&mut rig, &loc);
    assert_eq!(name_of(&failed), Some(ErrorName::NetworkUnreachable));
    assert!(matches!(rig.core.take().as_slice(), [Seen::Fetch(7)]));
}

fn account_data_failures(env: &Env) {
    let mut rig = rig_with(env, Duration::from_secs(10), Duration::from_millis(150));
    let loc = account(&mut rig, None);
    rig.core.give(None);
    let failed = connect(&mut rig, &loc).unwrap_err();
    assert_eq!((failed.name, failed.message.as_str()), (ErrorName::Timeout, "No account data"));
    let mut rig = rig_with(env, Duration::from_secs(10), Duration::from_secs(10));
    let loc = account(&mut rig, None);
    rig.core.give(None);
    let task = TaskContext::new(SessionId(3), Arc::new(AtomicBool::new(false)));
    let rx = on_worker(&mut rig, &loc, task.clone(), Box::new(|_, _, _| ((), Ok(()))));
    wait_until("the fetch", || rig.core.seen.lock().unwrap().iter().any(|s| matches!(s, Seen::Fetch(7))));
    task.cancel.store(true, Ordering::Release);
    rig.book.kick();
    assert_eq!(name_of(&get(&mut rig, &rx)), Some(ErrorName::Canceled));
    assert_eq!(env.fake.log_count("connect"), 0);
}

fn ad_hoc_identity_question(env: &Env) {
    let f = env.fake;
    f.set_identity_pin(&pin_for(b"k1"));
    let mut rig = rig(env);
    let host_key = "fake://fake.example:0";

    let declined = ad_hoc(&mut rig, Some(b"secret"));
    rig.core.answer(Some(Answer { accept: false, answers: Vec::new() }));
    let failed = connect(&mut rig, &declined).unwrap_err();
    assert_eq!(
        (failed.name, failed.message.as_str()),
        (ErrorName::ServerIdentityUnknown, "The server identity was not accepted")
    );
    let asks = rig.core.asks();
    assert_eq!(asks.len(), 1);
    let (kind, details) = &asks[0];
    assert_eq!(*kind, IDENTITY_UNKNOWN);
    assert_eq!(text(&details["location"]), declined);
    assert_eq!(text(&details["host"]), "fake.example");
    assert_eq!(text(&details["provider"]), "fake");
    assert!(text(&details["fingerprint"]).starts_with("SHA256:"));
    assert!(rig.pins.map.lock().unwrap().is_empty());
    rig.book.abandon_ad_hoc(&declined);

    let accepted = ad_hoc(&mut rig, Some(b"secret"));
    rig.core.answer(Some(Answer { accept: true, answers: Vec::new() }));
    connect(&mut rig, &accepted).unwrap();
    assert!(rig.book.add_ad_hoc(&accepted));
    assert_eq!(rig.core.asks().len(), 1);
    assert_eq!(rig.pins.pin(host_key), pin_for(b"k1"));
    rig.book.disconnect(&accepted);
    connect(&mut rig, &accepted).unwrap();
    assert_eq!(rig.core.asks().len(), 0);

    f.set_identity_pin(&pin_for(b"k2"));
    rig.book.disconnect(&accepted);
    let failed = connect(&mut rig, &accepted);
    assert_eq!(name_of(&failed), Some(ErrorName::ServerIdentityChanged));
    assert_eq!(rig.core.asks().len(), 0);

    rig.pins.map.lock().unwrap().clear();
    let gone = ad_hoc(&mut rig, Some(b"secret"));
    rig.core.answer(None);
    assert_eq!(name_of(&connect(&mut rig, &gone)), Some(ErrorName::ServerIdentityUnknown));
    rig.book.abandon_ad_hoc(&gone);

    rig.pins.read_only.store(true, Ordering::Release);
    let unsaved = ad_hoc(&mut rig, Some(b"secret"));
    rig.core.answer(Some(Answer { accept: true, answers: Vec::new() }));
    connect(&mut rig, &unsaved).unwrap();
    let seen = rig.core.take();
    assert!(
        seen.iter().any(|s| matches!(s, Seen::Warning(w) if w == "Cannot store an accepted server identity"))
    );
}

fn ad_hoc_secret_and_forget(env: &Env) {
    let f = env.fake;
    let mut rig = rig_with(env, Duration::from_millis(300), Duration::from_secs(10));
    let wrong = ad_hoc(&mut rig, Some(b"wrong"));
    assert_eq!(name_of(&connect(&mut rig, &wrong)), Some(ErrorName::AuthFailed));
    rig.book.abandon_ad_hoc(&wrong);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    connect(&mut rig, &id).unwrap();
    assert!(rig.book.add_ad_hoc(&id));
    f.set_credentials("", b"");
    let none = ad_hoc(&mut rig, None);
    connect(&mut rig, &none).unwrap();

    f.set_identity_pin(&pin_for(b"k1"));
    let unanswered = ad_hoc(&mut rig, None);
    let failed = connect(&mut rig, &unanswered);
    assert_eq!(name_of(&failed), Some(ErrorName::ServerIdentityUnknown));
    let seen = rig.core.take();
    assert!(seen.iter().any(|s| matches!(s, Seen::Withdrawn(_))), "{seen:?}");
    rig.book.abandon_ad_hoc(&unanswered);

    let pinned = ad_hoc(&mut rig, None);
    rig.core.answer(Some(Answer { accept: true, answers: Vec::new() }));
    connect(&mut rig, &pinned).unwrap();
    assert!(rig.book.add_ad_hoc(&pinned));
    assert!(!rig.pins.map.lock().unwrap().is_empty());
    assert!(rig.book.forget_ad_hoc(&pinned, &*rig.pins));
    assert!(rig.pins.map.lock().unwrap().is_empty());
    let again = ad_hoc(&mut rig, None);
    rig.core.answer(Some(Answer { accept: true, answers: Vec::new() }));
    connect(&mut rig, &again).unwrap();
    assert_eq!(rig.core.asks().len(), 2);
}

fn keyboard_interactive_question(env: &Env) {
    let f = env.fake;
    f.set_otp(b"246810");
    let mut rig = rig(env);
    let yes = |answers: &[&[u8]]| Answer {
        accept: true,
        answers: answers.iter().map(|a| Zeroizing::new(a.to_vec())).collect(),
    };
    let id = ad_hoc(&mut rig, Some(b"secret"));
    assert!(rig.book.add_ad_hoc(&id));
    rig.core.answer(Some(yes(&[b"246810"])));
    connect(&mut rig, &id).unwrap();
    let asks = rig.core.asks();
    assert_eq!(asks.len(), 1);
    let (kind, details) = &asks[0];
    assert_eq!(*kind, KEYBOARD_INTERACTIVE);
    assert_eq!(text(&details["name"]), "fake");
    assert_eq!(
        Vec::<String>::try_from(details["prompts"].try_clone().unwrap()).unwrap(),
        ["Verification code: "]
    );
    assert_eq!(f.log_count("answers:"), 1);
    for reply in [yes(&[b"246810", b"1"]), Answer { accept: false, answers: Vec::new() }] {
        rig.book.disconnect(&id);
        rig.core.answer(Some(reply));
        assert_eq!(name_of(&connect(&mut rig, &id)), Some(ErrorName::AuthFailed));
    }
    assert_eq!(f.log_count("answers:"), 1);
    f.set_credentials("user", b"");
    let loc = account(&mut rig, None);
    rig.core.answer(Some(yes(&[b"246810"])));
    connect(&mut rig, &loc).unwrap();
    assert_eq!(rig.core.asks().len(), 3);
}

fn connections_are_reused_and_dropped(env: &Env) {
    let f = env.fake;
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    assert!(rig.book.add_ad_hoc(&id));
    connect(&mut rig, &id).unwrap();
    connect(&mut rig, &id).unwrap();
    assert_eq!((f.log_count("connect"), f.live_backends()), (1, 1));
    let failing =
        |name: ErrorName| -> Body<()> { Box::new(move |_, _, _| ((), Err(Status::new(name, "x")))) };
    let rx = on_worker(&mut rig, &id, TaskContext::detached(), failing(ErrorName::NotFound));
    drop(get(&mut rig, &rx));
    connect(&mut rig, &id).unwrap();
    assert_eq!(f.log_count("connect"), 1);
    let rx = on_worker(&mut rig, &id, TaskContext::detached(), failing(ErrorName::ConnectionLost));
    drop(get(&mut rig, &rx));
    wait_until("the connection freed", || f.live_backends() == 0);
    connect(&mut rig, &id).unwrap();
    assert_eq!(f.log_count("connect"), 2);
    rig.book.disconnect(&id);
    wait_until("disconnected", || f.live_backends() == 0);
    connect(&mut rig, &id).unwrap();
    wait_until("idle", || {
        rig.book.maintain(Instant::now() + Duration::from_secs(61), Duration::from_mins(1))
    });
    wait_until("closed when idle", || f.live_backends() == 0);
    drop(rig);
    assert_eq!(f.live_backends(), 0);
}

fn cancel_kicks_a_running_listing(env: &Env) {
    let f = env.fake;
    for i in 0..40 {
        f.add_file(format!("/slow/f{i}").as_bytes(), b"x");
    }
    f.set_chunk_delay_ms(200);
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    connect(&mut rig, &id).unwrap();
    let task = TaskContext::new(SessionId(1), Arc::new(AtomicBool::new(false)));
    let (started_tx, started) = mpsc::channel();
    let rx = on_worker(
        &mut rig,
        &id,
        task.clone(),
        Box::new(move |conn, _, _| {
            let result = conn.list(b"/slow", 1, |_| {
                let _sent = started_tx.send(());
                true
            });
            (result.clone(), result)
        }),
    );
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    let start = Instant::now();
    task.cancel.store(true, Ordering::Release);
    rig.book.kick();
    assert_eq!(name_of(&get(&mut rig, &rx).unwrap()), Some(ErrorName::Canceled));
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    wait_until("the connection freed", || f.live_backends() == 0);
    f.set_chunk_delay_ms(0);
    connect(&mut rig, &id).unwrap();
    assert_eq!(f.log_count("connect"), 2);
}

fn list_streams_batches(env: &Env) {
    let f = env.fake;
    for i in 0..10 {
        f.add_file(format!("/dir/f{i}").as_bytes(), b"x");
    }
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    let budget = Arc::new(FlowBudget::new(usize::MAX));
    let run = |rig: &mut Rig, dir: &'static [u8], batch_size: u32, stop_after: usize| {
        let budget = Arc::clone(&budget);
        let rx = on_worker(
            rig,
            &id,
            TaskContext::detached(),
            Box::new(move |conn, _, _| {
                let cancel = AtomicBool::new(false);
                let mut batches: Vec<(Vec<WireEntry>, usize)> = Vec::new();
                let result = batch::list(conn, dir, batch_size, &budget, &cancel, |entries, bytes| {
                    batches.push((entries, bytes));
                    batches.len() < stop_after
                });
                ((batches, result.clone()), result)
            }),
        );
        get(rig, &rx).unwrap()
    };
    let (batches, result) = run(&mut rig, b"/dir", 4, usize::MAX);
    result.unwrap();
    assert_eq!(batches.iter().map(|b| b.0.len()).collect::<Vec<_>>(), [4, 4, 2]);
    for (entries, bytes) in &batches {
        assert_eq!(*bytes, entries.iter().map(batch::entry_wire_size).sum::<usize>());
    }
    assert_eq!(batches[2].0[1].name, b"f9");
    assert_eq!(budget.in_flight(), batches.iter().map(|b| b.1).sum::<usize>(), "the emitter owns the bytes");
    let (batches, result) = run(&mut rig, b"/dir", 4, 1);
    assert_eq!(name_of(&result), Some(ErrorName::Canceled));
    assert_eq!(batches.len(), 1);
    let (_, result) = run(&mut rig, b"/missing", 4, usize::MAX);
    assert_eq!(name_of(&result), Some(ErrorName::NotFound));
}

fn walk_and_remove_tree(env: &Env) {
    let f = env.fake;
    f.add_dir(b"/tree", None);
    f.add_dir(b"/tree/sub", None);
    for i in 0..600 {
        f.add_file(format!("/tree/sub/f{i}").as_bytes(), b"x");
    }
    f.add_file(b"/tree/top", b"y");
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    let walk_with = |rig: &mut Rig, opts: WalkOpts| {
        let rx = on_worker(
            rig,
            &id,
            TaskContext::detached(),
            Box::new(move |conn, _, _| {
                let budget = FlowBudget::new(usize::MAX);
                let cancel = AtomicBool::new(false);
                let mut items: Vec<Vec<WireWalkItem>> = Vec::new();
                let outcome = walk::walk(conn, b"/tree", &opts, &budget, &cancel, |batch, _| {
                    items.push(batch);
                    true
                });
                let result = outcome.result.clone();
                ((items, outcome), result)
            }),
        );
        get(rig, &rx).unwrap()
    };
    let (batches, outcome) = walk_with(&mut rig, WalkOpts::default());
    outcome.result.as_ref().unwrap();
    assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [512, 90]);
    assert_eq!(i64::try_from(&outcome.extra["entries"]).unwrap(), 602);
    let paths: Vec<&[u8]> = batches.iter().flatten().map(|i| i.path.as_slice()).collect();
    assert!(
        paths.contains(&&b"/tree/sub/f599"[..]) || paths.contains(&&b"sub/f599"[..]),
        "{:?}",
        &paths[..3]
    );
    let (batches, outcome) = walk_with(&mut rig, WalkOpts { max_depth: 0, ..WalkOpts::default() });
    outcome.result.as_ref().unwrap();
    assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 2, "the root's children only");

    let rx = on_worker(
        &mut rig,
        &id,
        TaskContext::detached(),
        Box::new(|conn, _, _| {
            let cancel = AtomicBool::new(false);
            let mut updates = Vec::new();
            let outcome =
                remove::remove_tree(conn, b"/tree", &cancel, |done, total| updates.push((done, total)));
            let result = outcome.result.clone();
            ((outcome, updates), result)
        }),
    );
    let (outcome, updates) = get(&mut rig, &rx).unwrap();
    outcome.result.as_ref().unwrap();
    assert_eq!(i64::try_from(&outcome.extra["files"]).unwrap(), 601);
    assert_eq!(i64::try_from(&outcome.extra["dirs"]).unwrap(), 2);
    assert!(!updates.is_empty() && updates.len() < 10, "throttled: {}", updates.len());
    assert!(!f.exists(b"/tree"));
    f.add_dir(b"/t2", None);
    f.add_file(b"/t2/a", b"");
    let rx = on_worker(
        &mut rig,
        &id,
        TaskContext::detached(),
        Box::new(|conn, _, _| {
            let cancel = AtomicBool::new(true);
            let outcome = remove::remove_tree(conn, b"/t2", &cancel, |_, _| {});
            (outcome.result, Ok(()))
        }),
    );
    assert_eq!(name_of(&get(&mut rig, &rx).unwrap()), Some(ErrorName::Canceled));
}

fn read_handles_live_on_their_worker(env: &Env) {
    let f = env.fake;
    f.add_file(b"/r", b"hello world");
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));
    assert!(rig.book.add_ad_hoc(&id));
    let rx = on_worker(
        &mut rig,
        &id,
        TaskContext::detached(),
        Box::new(|conn, handles, worker| match conn.open_read(b"/r") {
            Ok((handle, size)) => ((handles.add(handle), size, worker), Ok(())),
            Err(e) => panic!("{e}"),
        }),
    );
    let (handle, size, worker) = get(&mut rig, &rx).unwrap();
    assert_eq!(size, 11);
    let (tx, rx) = mpsc::channel();
    rig.book.submit_to(
        &id,
        worker,
        TaskContext::detached(),
        wrap(
            tx,
            Box::new(move |_, handles, _| {
                let mut buf = [0u8; 5];
                let n = handles.get_mut(handle).unwrap().read(6, &mut buf).unwrap();
                (buf[..n].to_vec(), Ok(()))
            }),
        ),
    );
    assert_eq!(get(&mut rig, &rx).unwrap(), b"world");
    assert_eq!(f.log_count("close"), 0);
    rig.book.close_worker_handle(&id, worker, handle);
    wait_until("the handle closed", || f.log_count("close") == 1);
}

fn temp_path(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("backend-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn transfer_job(
    rig: &mut Rig,
    loc: &str,
    job: transfer::Transfer,
) -> (netvfs_bridge::jobs::JobOutcome, Vec<(i64, i64)>) {
    let rx = on_worker(
        rig,
        loc,
        TaskContext::detached(),
        Box::new(move |conn, _, _| {
            let cancel = AtomicBool::new(false);
            let mut updates = Vec::new();
            let outcome = transfer::transfer(conn, &job, &cancel, |d, t| updates.push((d, t)));
            let result = outcome.result.clone();
            ((outcome, updates), result)
        }),
    );
    get(rig, &rx).unwrap()
}

fn checked(fd: OwnedFd, access: FdAccess) -> (OwnedFd, FdInfo) {
    let info = check_transfer_fd(fd.as_raw_fd(), access).unwrap();
    (fd, info)
}

fn bytes_of(outcome: &netvfs_bridge::jobs::JobOutcome) -> i64 {
    i64::try_from(&outcome.extra["bytes"]).unwrap()
}

fn transfers_of_regular_files(env: &Env) {
    let f = env.fake;
    let data = pattern(300_000);
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));

    let path = temp_path("up");
    std::fs::write(&path, &data).unwrap();
    let (fd, info) = checked(File::open(&path).unwrap().into(), FdAccess::Read);
    assert_eq!(info, FdInfo { fifo: false, size: 300_000 });
    let opts = TransferOpts { offset: 1000, mtime_ms: Some(1_600_000_000_000), ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/up".to_vec(), opts, upload: true };
    let (outcome, updates) = transfer_job(&mut rig, &id, job);
    outcome.result.as_ref().unwrap();
    assert_eq!(bytes_of(&outcome), 299_000);
    assert_eq!(f.file_data(b"/up").unwrap(), data[1000..]);
    assert_ne!(updates.len(), 0);
    let (fd, info) = checked(File::open(&path).unwrap().into(), FdAccess::Read);
    let job =
        transfer::Transfer { fd, info, path: b"/up".to_vec(), opts: TransferOpts::default(), upload: true };
    assert_eq!(name_of(&transfer_job(&mut rig, &id, job).0.result), Some(ErrorName::AlreadyExists));
    let (fd, info) = checked(File::open(&path).unwrap().into(), FdAccess::Read);
    let opts = TransferOpts {
        offset: 5,
        size: 10,
        disposition: Disposition::Truncate,
        create_mode: Some(0o600),
        ..TransferOpts::default()
    };
    let job = transfer::Transfer { fd, info, path: b"/up".to_vec(), opts, upload: true };
    transfer_job(&mut rig, &id, job).0.result.unwrap();
    assert_eq!(f.file_data(b"/up").unwrap(), data[5..15]);
    let (fd, info) = checked(File::open(&path).unwrap().into(), FdAccess::Read);
    let opts =
        TransferOpts { offset: 10, size: -1, disposition: Disposition::Resume, ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/up".to_vec(), opts, upload: true };
    let (outcome, _) = transfer_job(&mut rig, &id, job);
    outcome.result.as_ref().unwrap();
    assert_eq!(bytes_of(&outcome), 299_990);
    let mut expected = data[5..15].to_vec();
    expected.extend_from_slice(&data[10..]);
    assert_eq!(f.file_data(b"/up").unwrap(), expected);

    f.add_file(b"/down", &data);
    let local = temp_path("down");
    std::fs::write(&local, b"0123456789").unwrap();
    let file = OpenOptions::new().write(true).open(&local).unwrap();
    let (fd, info) = checked(file.into(), FdAccess::Write);
    let opts = TransferOpts { offset: 10, ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/down".to_vec(), opts, upload: false };
    let (outcome, _) = transfer_job(&mut rig, &id, job);
    outcome.result.as_ref().unwrap();
    assert_eq!(bytes_of(&outcome), 299_990);
    let got = std::fs::read(&local).unwrap();
    assert_eq!((&got[..10], &got[10..]), (&b"0123456789"[..], &data[10..]));
    let file = OpenOptions::new().write(true).truncate(true).open(&local).unwrap();
    let (fd, info) = checked(file.into(), FdAccess::Write);
    let opts = TransferOpts { offset: 0, size: 100, ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/down".to_vec(), opts, upload: false };
    transfer_job(&mut rig, &id, job).0.result.unwrap();
    assert_eq!(std::fs::read(&local).unwrap(), data[..100]);
    let read_only = File::open(&local).unwrap();
    assert_eq!(
        check_transfer_fd(read_only.as_raw_fd(), FdAccess::Write).unwrap_err().name,
        ErrorName::PermissionDenied
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn transfers_through_pipes(env: &Env) {
    let f = env.fake;
    let data = pattern(200_000);
    let mut rig = rig(env);
    let id = ad_hoc(&mut rig, Some(b"secret"));

    let (r, mut w) = std::io::pipe().unwrap();
    let (fd, info) = checked(r.into(), FdAccess::Read);
    assert_eq!(info, FdInfo { fifo: true, size: -1 });
    let writer = {
        let data = data.clone();
        thread::spawn(move || w.write_all(&data).unwrap())
    };
    let opts = TransferOpts { offset: 99, ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/piped".to_vec(), opts, upload: true };
    let (outcome, _) = transfer_job(&mut rig, &id, job);
    writer.join().unwrap();
    outcome.result.as_ref().unwrap();
    assert_eq!(f.file_data(b"/piped").unwrap(), data);
    assert_eq!(bytes_of(&outcome), 200_000);

    let (mut r, w) = std::io::pipe().unwrap();
    let (fd, info) = checked(w.into(), FdAccess::Write);
    let reader = thread::spawn(move || {
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        got
    });
    let opts = TransferOpts { offset: 100, ..TransferOpts::default() };
    let job = transfer::Transfer { fd, info, path: b"/piped".to_vec(), opts, upload: false };
    let (outcome, _) = transfer_job(&mut rig, &id, job);
    outcome.result.as_ref().unwrap();
    assert_eq!(reader.join().unwrap(), data[100..]);

    let (r, w) = std::io::pipe().unwrap();
    drop(r);
    let (fd, info) = checked(w.into(), FdAccess::Write);
    let job = transfer::Transfer {
        fd,
        info,
        path: b"/piped".to_vec(),
        opts: TransferOpts::default(),
        upload: false,
    };
    let (outcome, _) = transfer_job(&mut rig, &id, job);
    assert!(outcome.result.is_err());
    assert_eq!(bytes_of(&outcome), 0);
}

fn copy_jobs_use_two_connections(env: &Env) {
    let f = env.fake;
    f.add_file(b"/src/a", b"aaa");
    f.add_file(b"/src/b", b"bb");
    let mut rig = rig(env);
    let source = ad_hoc(&mut rig, Some(b"secret"));
    assert!(rig.book.add_ad_hoc(&source));
    let destination = ad_hoc(&mut rig, Some(b"secret"));
    assert!(rig.book.add_ad_hoc(&destination));
    let backend = Arc::clone(rig.book.pools().backend());
    assert!(format!("{backend:?}").starts_with("Connector"));
    let mut jobs = CopyJobs::new(backend, rig.core.events());
    let task = TaskContext::detached();
    let spec = |id: &str| Arc::clone(rig.book.find(id).unwrap());
    let (src, dst) = (spec(&source), spec(&destination));
    let id = jobs
        .start(
            rig.book.pools_mut(),
            src,
            dst,
            task,
            Box::new(|from, to| from.copy_across(b"/src", to, b"/dst", (true, false), None)),
        )
        .unwrap();
    wait_until("the copy", || rig.core.seen.lock().unwrap().iter().any(|s| matches!(s, Seen::CopyDone(..))));
    let seen = rig.core.take();
    assert!(matches!(seen.as_slice(), [Seen::CopyDone(done, Ok(()))] if *done == id), "{seen:?}");
    assert!(jobs.finish(id, rig.book.pools_mut()));
    assert_eq!(f.file_data(b"/dst/a").unwrap(), b"aaa");
    assert_eq!(f.file_data(b"/dst/b").unwrap(), b"bb");
    assert_eq!(f.log_count("connect"), 2);
    assert_eq!(f.live_backends(), 0);
    assert_eq!(rig.book.pools().hosts().in_use("fake://fake.example:0"), 0);
}
