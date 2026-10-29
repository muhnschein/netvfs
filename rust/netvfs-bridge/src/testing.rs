// SPDX-License-Identifier: LGPL-2.1-or-later
//! Test support for the whole bridge (feature `testing`; design §4.1): the
//! harness of test binaries that need the C ABI ([`run_main`]), and the
//! [`Fixture`], the port of `tests/bridge/common/bridgetest.h`: the bridge
//! in-process, on a runtime thread of its own, against the real
//! `libnetvfs-bridge-ffi.so` and the fake backend, with fake accounts, a
//! fake prompt, a fake discovery, a recording handoff launcher and fake
//! drives, listening on `unix:path=<tmp>/bridge.sock`. Clients are
//! [`netvfs_bridge_proto::Connection`]s; a [`Probe`] reads the core's
//! counters.
//!
//! The C ABI comes from the variables of [`VARIABLES`]; without them
//! [`run_main`] says every test is skipped. A failing set-up is a failing
//! test, so these helpers panic.
#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc, clippy::print_stdout)]

use crate::accounts::{AccountDirectory, AccountLocation, Attention, ConnectionParams, FilesAccess};
use crate::config::ConsumerInfo;
use crate::consent::{Consent, ConsentStore};
use crate::core::nearby::NearbySource;
use crate::core::{Config, CoreLink, Counters, Deps, LocalFuture, MakeServices, Services};
use crate::drives::classify::Kind;
use crate::drives::{Drive, DriveSource};
use crate::ffi::fake::{self, Fake};
use crate::ffi::{Ffi, Params, ParsedUrl};
use crate::handoff::{HandoffCall, Launcher};
use crate::prompt::{ConsentPrompt, PromptEvent};
use crate::server::ListenAddress;
use crate::status::Status;
use crate::testutil::TempDir;
use netvfs_bridge_proto::{BridgeError, Connection, Signal, SignalStream};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The variables that name the C ABI, the fake's control table and the
/// fake backend's folder (`make check-rust-ffi` sets them).
pub const VARIABLES: [&str; 3] = [crate::ffi::PATH_ENV, fake::PATH_ENV, "NETVFS_BACKEND_PATH"];
/// The fixture's consumer.
pub const CONSUMER: &str = "test";
/// The location of the fixture's account 1.
pub const ACCOUNT_LOC: &str = "account:1";
/// The fixture's idle exit unless a test sets one: long, so that the
/// bridge stays while a test runs (the fixture stops it when dropped).
pub const FIXTURE_IDLE_EXIT: Duration = Duration::from_secs(30);
/// How long a test may run before the harness gives up on it.
pub const HANG: Duration = Duration::from_mins(1);
/// How long the waits of these helpers wait by default.
pub const WAIT: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------- harness

/// The C ABI and the fake backend's control table.
#[derive(Debug, Clone, Copy)]
pub struct Harness {
    /// The loaded C ABI (`init` done on the main thread).
    pub ffi: Ffi,
    /// The fake backend's control table.
    pub fake: Fake,
}

impl Harness {
    /// Loads both libraries; `None` when a variable of [`VARIABLES`] is
    /// not set.
    #[must_use]
    pub fn load() -> Option<Self> {
        if VARIABLES.iter().any(|v| std::env::var_os(v).is_none()) {
            return None;
        }
        let ffi = Ffi::load().unwrap_or_else(|e| panic!("{e}"));
        let Some(fake) = Fake::from_env() else { panic!("{} is set but not seen", fake::PATH_ENV) };
        let fake = fake.unwrap_or_else(|e| panic!("{e}"));
        Some(Self { ffi, fake })
    }
}

/// A test of a [`run_main`] binary.
pub type Test = fn(&Harness);

fn selected(tests: &[(&'static str, Test)], args: &[String]) -> Vec<(&'static str, Test)> {
    let exact = args.iter().any(|a| a == "--exact");
    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    tests
        .iter()
        .copied()
        .filter(|(name, _)| {
            filters.is_empty()
                || filters.iter().any(|f| if exact { name == f } else { name.contains(f.as_str()) })
        })
        .collect()
}

/// The `main` of a test binary with `harness = false`: lists the tests
/// (`--list`, for nextest), skips them all without the C ABI, otherwise
/// `init`s the Qt application as `app` on this (main) thread and runs each
/// selected test on a thread of its own while this one serves the Qt event
/// loop; the fake backend is reset before each test.
#[must_use]
pub fn run_main(app: &str, tests: &[(&'static str, Test)]) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--list") {
        if !args.iter().any(|a| a == "--ignored") {
            for (name, _) in tests {
                println!("{name}: test");
            }
        }
        return ExitCode::SUCCESS;
    }
    let tests = selected(tests, &args);
    let Some(h) = Harness::load() else {
        println!("skipped: {} not set (make check-rust-ffi sets them)", VARIABLES.join(", "));
        return ExitCode::SUCCESS;
    };
    h.ffi.init(app).expect("init on the main thread");
    let mut failed = 0_usize;
    for (name, test) in tests {
        h.fake.reset();
        let watchdog = watch(name);
        let ok = off_qt_thread(h, move |h| catch_unwind(AssertUnwindSafe(|| test(h))).is_ok());
        drop(watchdog);
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        failed = failed.saturating_add(usize::from(!ok));
    }
    h.ffi.shutdown().expect("shutdown");
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Ends the process when `name` runs longer than [`HANG`].
#[allow(clippy::exit, reason = "a hung test cannot be stopped otherwise")]
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

/// Ends the Qt loop when the test thread is done.
struct QuitOnDrop(Ffi);

impl Drop for QuitOnDrop {
    fn drop(&mut self) {
        self.0.quit(0);
    }
}

/// Waits until the Qt loop runs.
fn wait_for_loop(ffi: Ffi) {
    let (tx, rx) = mpsc::channel();
    loop {
        let tx = tx.clone();
        if ffi.post(move || {
            let _sent = tx.send(());
        }) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    rx.recv().expect("the Qt loop runs");
}

/// Runs `work` on another thread while this one runs the Qt event loop.
fn off_qt_thread<R: Send>(h: Harness, work: impl FnOnce(&Harness) -> R + Send) -> R {
    thread::scope(|s| {
        let worker = s.spawn(move || {
            let _quit = QuitOnDrop(h.ffi);
            wait_for_loop(h.ffi);
            work(&h)
        });
        assert_eq!(h.ffi.run(), Ok(0));
        worker.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Runs `f` to completion on a current-thread runtime of this thread
/// (clients need one for their connection's tasks).
pub fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime").block_on(f)
}

/// Waits until `done` holds, at most `timeout`; whether it did.
pub async fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now().checked_add(timeout).expect("a deadline");
    while !done() {
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// The next signal that `wanted` accepts, skipping others; `None` after
/// `timeout` or when the connection ends.
pub async fn wait_signal(
    signals: &mut SignalStream,
    timeout: Duration,
    mut wanted: impl FnMut(&Signal) -> bool,
) -> Option<Signal> {
    use futures_lite::StreamExt as _;
    tokio::time::timeout(timeout, async {
        while let Some(signal) = signals.next().await {
            if let Ok(signal) = signal
                && wanted(&signal)
            {
                return Some(signal);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Waits until the connection behind `signals` ends; whether it did within
/// `timeout`.
pub async fn wait_disconnected(signals: &mut SignalStream, timeout: Duration) -> bool {
    use futures_lite::StreamExt as _;
    tokio::time::timeout(timeout, async {
        while let Some(item) = signals.next().await {
            if item.is_err() {
                break;
            }
        }
    })
    .await
    .is_ok()
}

/// The D-Bus error name of a failed call (`org.netvfs.Error.NotFound`,
/// `org.freedesktop.DBus.Error.InvalidArgs`); `None` on success.
pub fn error_name<T>(result: &Result<T, zbus::Error>) -> Option<String> {
    result.as_ref().err().and_then(|e| BridgeError::from(e.clone()).dbus_name().map(str::to_owned))
}

// --------------------------------------------------------------- fakes

/// What the fake accounts hold and saw.
#[derive(Debug, Default)]
pub struct AccountsState {
    /// The listed accounts.
    pub accounts: Vec<AccountLocation>,
    /// `files` answers this failure instead of an account's data.
    pub files_error: Option<Status>,
    /// `files` calls.
    pub fetches: usize,
    /// `set_attention` calls.
    pub attention: Vec<(i32, Attention, String)>,
    /// `files` never answers.
    pub hang: bool,
}

/// An [`AccountDirectory`] in memory (`FakeAccounts` of bridgetest.cpp).
#[derive(Debug, Clone, Default)]
pub struct FakeAccounts(pub Arc<Mutex<AccountsState>>);

impl FakeAccounts {
    /// Account `id` of the fake backend: provider `fake`, `Fake <id>` at
    /// `fake.example` with user `user`, files at `/`.
    #[must_use]
    pub fn fake_account(id: i32) -> AccountLocation {
        AccountLocation {
            account_id: id,
            provider: "fake".to_owned(),
            display_name: format!("Fake {id}"),
            params: ConnectionParams {
                provider: "fake".to_owned(),
                host: "fake.example".to_owned(),
                username: "user".to_owned(),
                ..ConnectionParams::default()
            },
            files_root: b"/".to_vec(),
            attention: Attention::None,
        }
    }

    /// The state, locked.
    pub fn state(&self) -> MutexGuard<'_, AccountsState> {
        lock(&self.0)
    }
}

impl AccountDirectory for FakeAccounts {
    fn list(&self) -> impl Future<Output = Vec<AccountLocation>> {
        std::future::ready(self.state().accounts.clone())
    }

    async fn files(&self, id: i32) -> Result<FilesAccess, Status> {
        let hang = {
            let mut state = self.state();
            state.fetches = state.fetches.saturating_add(1);
            state.hang
        };
        if hang {
            return std::future::pending().await;
        }
        let state = self.state();
        if let Some(error) = &state.files_error {
            return Err(error.clone());
        }
        let params = state.accounts.iter().find(|a| a.account_id == id).map(|a| a.params.clone());
        drop(state);
        // XA-7: credentials id 0 with an optional secret, as the fake backend
        // is set up by the fixture (user `user`, empty secret).
        params
            .map(|params| FilesAccess { params, credentials_id: 0, secret_optional: true })
            .ok_or_else(|| Status::new(netvfs_bridge_proto::ErrorName::NotFound, "No such account"))
    }

    async fn set_attention(&self, id: i32, attention: Attention, pin: &str) {
        self.state().attention.push((id, attention, pin.to_owned()));
    }
}

/// What the fake prompt saw.
#[derive(Debug, Default)]
pub struct PromptState {
    /// `show` calls.
    pub shown: usize,
    /// `withdraw` calls.
    pub withdrawn: usize,
    /// Whether the question is up.
    pub visible: bool,
    /// The display name of the last `show`.
    pub display_name: String,
}

/// A [`ConsentPrompt`] that tests answer ([`Fixture::answer_prompt`]).
#[derive(Debug, Clone, Default)]
pub struct FakePrompt(pub Arc<Mutex<PromptState>>);

impl FakePrompt {
    /// The state, locked.
    pub fn state(&self) -> MutexGuard<'_, PromptState> {
        lock(&self.0)
    }
}

impl ConsentPrompt for FakePrompt {
    fn show(&mut self, display_name: &str) {
        let mut state = self.state();
        state.shown = state.shown.saturating_add(1);
        state.visible = true;
        display_name.clone_into(&mut state.display_name);
    }

    fn withdraw(&mut self) {
        let mut state = self.state();
        state.withdrawn = state.withdrawn.saturating_add(1);
        state.visible = false;
    }

    fn is_shown(&self) -> bool {
        self.state().visible
    }
}

/// A [`NearbySource`] that records its starts and stops; tests report
/// servers through [`Fixture::link`].
#[derive(Debug, Clone, Default)]
pub struct FakeNearby(pub Arc<Mutex<Vec<bool>>>);

impl FakeNearby {
    /// The `set_running` calls so far.
    #[must_use]
    pub fn calls(&self) -> Vec<bool> {
        lock(&self.0).clone()
    }
}

impl NearbySource for FakeNearby {
    fn set_running(&mut self, on: bool) {
        lock(&self.0).push(on);
    }
}

/// A [`Launcher`] that records the handoff calls.
#[derive(Debug, Clone, Default)]
pub struct RecordingLauncher(pub Arc<Mutex<Vec<HandoffCall>>>);

impl RecordingLauncher {
    /// The calls so far.
    #[must_use]
    pub fn calls(&self) -> Vec<HandoffCall> {
        lock(&self.0).clone()
    }
}

impl Launcher for RecordingLauncher {
    fn launch(&self, call: &HandoffCall) -> Result<(), Status> {
        lock(&self.0).push(call.clone());
        Ok(())
    }
}

/// What the fake drives hold and saw.
#[derive(Debug, Default)]
pub struct DrivesState {
    /// What `ListDrives` lists.
    pub drives: Vec<Drive>,
    /// `Mount` (true) and `Unmount` (false) calls, with their drive.
    pub calls: Vec<(bool, String)>,
    /// The next `Mount` or `Unmount` fails with this.
    pub error: Option<Status>,
}

/// A [`DriveSource`] in memory that mounts at `/run/media/user/<id>`;
/// tests report changes through [`Fixture::drives_changed`].
#[derive(Debug, Clone, Default)]
pub struct FakeDrives(pub Arc<Mutex<DrivesState>>);

impl FakeDrives {
    /// A memory card `id` labelled `label`, not mounted.
    #[must_use]
    pub fn card(id: &str, label: &str) -> Drive {
        Drive {
            id: id.to_owned(),
            label: label.to_owned(),
            mount_point: Vec::new(),
            kind: Kind::Sd,
            size: 1 << 30,
            fs_type: "vfat".to_owned(),
            read_only: false,
            uuid: String::new(),
            model: String::new(),
            locked: false,
        }
    }

    /// The state, locked.
    pub fn state(&self) -> MutexGuard<'_, DrivesState> {
        lock(&self.0)
    }

    fn act(&self, id: &str, mount: bool) -> Result<Vec<u8>, Status> {
        let mut state = self.state();
        state.calls.push((mount, id.to_owned()));
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        let drive = state.drives.iter_mut().find(|d| d.id == id);
        let drive =
            drive.ok_or_else(|| Status::new(netvfs_bridge_proto::ErrorName::NotFound, "No such drive"))?;
        drive.mount_point = if mount { format!("/run/media/user/{id}").into_bytes() } else { Vec::new() };
        let point = drive.mount_point.clone();
        drop(state);
        Ok(point)
    }
}

impl DriveSource for FakeDrives {
    fn list(&self) -> LocalFuture<'_, Vec<Drive>> {
        Box::pin(std::future::ready(self.state().drives.clone()))
    }

    fn mount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<Vec<u8>, Status>> {
        Box::pin(std::future::ready(self.act(id, true)))
    }

    fn unmount<'a>(&'a self, id: &'a str) -> LocalFuture<'a, Result<(), Status>> {
        Box::pin(std::future::ready(self.act(id, false).map(drop)))
    }
}

// ------------------------------------------------------------- fixture

/// The core's counters, read through its channel.
#[derive(Debug, Clone)]
pub struct Probe(CoreLink);

impl Probe {
    /// A probe of the core behind `link`.
    #[must_use]
    pub const fn new(link: CoreLink) -> Self {
        Self(link)
    }

    /// The counters now; `None` once the core has stopped.
    pub async fn counters(&self) -> Option<Counters> {
        self.0.probe().await
    }

    /// Waits until the counters satisfy `done`, at most `timeout`; the
    /// last counters seen.
    pub async fn wait_until(
        &self,
        timeout: Duration,
        mut done: impl FnMut(&Counters) -> bool,
    ) -> Option<Counters> {
        let end = Instant::now().checked_add(timeout).expect("a deadline");
        loop {
            let counters = self.counters().await?;
            if done(&counters) || Instant::now() >= end {
                return Some(counters);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// The bridge of consumer `test` in-process (`Fixture` of bridgetest.cpp).
#[derive(Debug)]
pub struct Fixture {
    /// The C ABI and the fake backend.
    pub harness: Harness,
    /// The temporary folder: `config/bridge.conf`, `known_hosts`,
    /// `handoff.conf`, `bridge.sock`.
    pub dir: TempDir,
    /// What the bridge runs with.
    pub config: Config,
    /// The listening socket.
    pub socket: PathBuf,
    /// The accounts (account 1 at the start).
    pub accounts: FakeAccounts,
    /// The consent question.
    pub prompt: FakePrompt,
    /// The discovery of nearby servers.
    pub nearby: FakeNearby,
    /// The settings handoff.
    pub launcher: RecordingLauncher,
    /// The drives (none at the start).
    pub drives: FakeDrives,
    link: CoreLink,
    bridge: Option<JoinHandle<ExitCode>>,
}

/// How a [`Fixture`] starts.
#[derive(Debug, Clone)]
pub struct Setup {
    /// The consent stored before the start.
    pub consent: Consent,
    /// The idle exit.
    pub idle_exit: Duration,
    /// The consumer's registered executable; `None`: this test binary.
    pub executable: Option<String>,
    /// The content of `handoff.conf`; `None`: no file.
    pub handoff_conf: Option<String>,
    /// `files` never answers (`HangingAccounts`).
    pub hang_accounts: bool,
    /// Pooled connections without work are closed after this (at the
    /// core's next maintenance).
    pub connection_idle: Duration,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            consent: Consent::Granted,
            idle_exit: FIXTURE_IDLE_EXIT,
            executable: None,
            handoff_conf: None,
            hang_accounts: false,
            connection_idle: crate::locations::pool::CONNECTION_IDLE,
        }
    }
}

/// `fake://[user@]host[/path]`: an ad-hoc location of the fake backend
/// (which has no URL scheme of its own); other URLs go to the C ABI.
#[must_use]
pub fn fake_url(url: &str) -> Option<ParsedUrl> {
    let rest = url.strip_prefix("fake://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (user, host) = authority.split_once('@').map_or(("", authority), |(u, h)| (u, h));
    let params = Params {
        provider: "fake".to_owned(),
        host: host.to_owned(),
        username: user.to_owned(),
        ..Params::default()
    };
    Some(ParsedUrl { params, path: format!("/{path}").into_bytes() })
}

impl Fixture {
    /// The bridge with `consent` stored, the fixture's idle exit.
    #[must_use]
    pub fn new(harness: &Harness, consent: Consent) -> Self {
        Self::start(harness, Setup { consent, ..Setup::default() })
    }

    /// The bridge with `consent` stored and the idle exit `idle_exit`.
    #[must_use]
    pub fn with_idle_exit(harness: &Harness, consent: Consent, idle_exit: Duration) -> Self {
        Self::start(harness, Setup { consent, idle_exit, ..Setup::default() })
    }

    /// The bridge as `setup` says.
    #[must_use]
    pub fn start(harness: &Harness, setup: Setup) -> Self {
        let h = *harness;
        // XA-7: the fake server takes the account's empty optional secret.
        h.fake.set_credentials("user", b"");
        let dir = TempDir::new();
        let socket = dir.join("bridge.sock");
        let executable = setup.executable.unwrap_or_else(|| {
            std::env::current_exe().expect("the test's executable").to_string_lossy().into_owned()
        });
        let config = Config {
            consumer: ConsumerInfo {
                id: CONSUMER.to_owned(),
                display_name: "Test".to_owned(),
                executable,
                data_dir: "data".to_owned(),
            },
            consent_file: dir.join("config/bridge.conf"),
            known_hosts_file: dir.join("known_hosts"),
            handoff_config: dir.join("handoff.conf"),
            idle_exit: setup.idle_exit,
            connection_idle: setup.connection_idle,
            question_timeout: crate::locations::connector::QUESTION_TIMEOUT,
        };
        if let Some(conf) = &setup.handoff_conf {
            std::fs::write(&config.handoff_config, conf).expect("handoff.conf");
        }
        let accounts = FakeAccounts::default();
        accounts.state().accounts.push(FakeAccounts::fake_account(1));
        accounts.state().hang = setup.hang_accounts;
        let (prompt, nearby, launcher, drives) = (
            FakePrompt::default(),
            FakeNearby::default(),
            RecordingLauncher::default(),
            FakeDrives::default(),
        );
        ConsentStore::new(&config.consent_file).set_consent(CONSUMER, setup.consent).expect("bridge.conf");
        let (ready, linked) = mpsc::channel::<CoreLink>();
        let services: MakeServices = {
            let (accounts, prompt, nearby, launcher, drives) =
                (accounts.clone(), prompt.clone(), nearby.clone(), launcher.clone(), drives.clone());
            Box::new(move |link| {
                drop(ready.send(link));
                Box::pin(async move {
                    Services {
                        accounts: Rc::new(accounts),
                        prompt: Box::new(prompt),
                        nearby: Box::new(nearby),
                        launcher: Box::new(launcher),
                        drives: Rc::new(drives),
                    }
                })
            })
        };
        let deps = Deps {
            ffi: h.ffi,
            listen: ListenAddress::Path(socket.clone()),
            services,
            url_override: Some(Arc::new(fake_url)),
        };
        let run = config.clone();
        let bridge = thread::Builder::new()
            .name("nvb-rt".to_owned())
            .spawn(move || crate::serve(run, deps))
            .expect("the runtime thread");
        let link = match linked.recv_timeout(WAIT) {
            Ok(link) => link,
            Err(e) => panic!("the bridge did not start ({e}): {:?}", bridge.join().ok()),
        };
        Self {
            harness: h,
            dir,
            config,
            socket,
            accounts,
            prompt,
            nearby,
            launcher,
            drives,
            link,
            bridge: Some(bridge),
        }
    }

    /// The accounts changed (the helper's `AccountChanged`).
    pub fn accounts_changed(&self) {
        assert!(self.link.accounts_changed(), "the core has stopped");
    }

    /// The drives changed (UDisks2's signals).
    pub fn drives_changed(&self) {
        assert!(self.link.drives_changed(), "the core has stopped");
    }

    /// Stores `consent` in `bridge.conf`, as netvfs-ui does.
    pub fn set_consent(&self, consent: Consent) {
        ConsentStore::new(&self.config.consent_file).set_consent(CONSUMER, consent).expect("bridge.conf");
    }

    /// The consent stored in `bridge.conf`.
    #[must_use]
    pub fn stored_consent(&self) -> Consent {
        ConsentStore::new(&self.config.consent_file).consent(CONSUMER)
    }

    /// The user answers the shown consent question.
    pub fn answer_prompt(&self, allow: bool) {
        self.prompt.state().visible = false;
        assert!(self.link.prompt(PromptEvent::Answered(allow)), "the core has stopped");
    }

    /// The way into the core (discovery results, account changes).
    #[must_use]
    pub const fn link(&self) -> &CoreLink {
        &self.link
    }

    /// The core's counters.
    #[must_use]
    pub fn probe(&self) -> Probe {
        Probe::new(self.link.clone())
    }

    /// A connected client that has not said Hello.
    pub async fn client(&self) -> Connection {
        netvfs_bridge_proto::connect(&self.socket).await.expect("connected")
    }

    /// A connected client after `Hello`.
    pub async fn hello_client(&self) -> Connection {
        let c = self.client().await;
        c.proxy().hello("fixture").await.expect("Hello");
        c
    }

    /// Waits until the bridge stopped by itself (the idle exit), at most
    /// `timeout`: its exit code.
    pub async fn wait_exit(&mut self, timeout: Duration) -> Option<ExitCode> {
        let finished = wait_for(timeout, || self.bridge.as_ref().is_some_and(JoinHandle::is_finished)).await;
        if !finished {
            return None;
        }
        self.bridge.take().and_then(|b| b.join().ok())
    }

    /// Stops the bridge: its exit code.
    pub fn stop(&mut self) -> Option<ExitCode> {
        let _stopping = self.link.shutdown();
        self.bridge.take().and_then(|b| b.join().ok())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _code = self.stop();
    }
}

// ---------------------------------------------------------- the binary

/// The fake helper's table: account 1 as the [`Fixture`] has it (provider
/// `fake`, "Fake 1" at `fake.example`, user `user`, files at `/`).
const FAKE_ACCOUNTS: &str = "account\t1\tfake\tFake 1\tfake.example\t0\tuser\t/\t\n";

/// The `netvfs-bridge` binary as a test runs it (the process, contract and
/// notification tests): consumer `id`, registered with this test binary as
/// its executable, and a private home, configuration, data and consumers
/// folder below [`BridgeRun::dir`]; no accounts helper, no session bus,
/// the idle exit after 500 ms. The `with_*` methods change that before
/// [`BridgeRun::spawn`].
#[derive(Debug)]
pub struct BridgeRun {
    /// The temporary folder: `home`, `config`, `data`, `consumers`,
    /// `bridge.sock`.
    pub dir: TempDir,
    /// The consumer.
    pub consumer: String,
    /// Where the bridge listens.
    pub socket: PathBuf,
    /// The command; arguments and environment set.
    pub command: std::process::Command,
}

impl BridgeRun {
    /// The bridge at `bridge` with `--listen unix:path=<dir>/bridge.sock`.
    #[must_use]
    pub fn new(bridge: &std::path::Path, consumer: &str) -> Self {
        let mut run = Self::bare(bridge, consumer);
        run.command.arg("--listen").arg(format!("unix:path={}", run.socket.display())).arg(consumer);
        run
    }

    /// The bridge at `bridge` without arguments (the test adds them) and
    /// not socket-activated.
    #[must_use]
    pub fn bare(bridge: &std::path::Path, consumer: &str) -> Self {
        let dir = TempDir::new();
        let socket = dir.join("bridge.sock");
        let mut command = std::process::Command::new(bridge);
        command.env_remove("LISTEN_FDS").env_remove("LISTEN_PID");
        Self::prepare(dir, consumer, socket, command)
    }

    /// The bridge at `bridge` socket-activated, as systemd starts it:
    /// listening on `<dir>/bridge.sock`, bound here and passed as fd 3
    /// ([`crate::testutil::socket_activated`]).
    #[must_use]
    pub fn activated(bridge: &std::path::Path, consumer: &str) -> Self {
        let dir = TempDir::new();
        let socket = dir.join("bridge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("the listening socket");
        let mut command = crate::testutil::socket_activated(bridge, listener.into());
        command.arg(consumer);
        Self::prepare(dir, consumer, socket, command)
    }

    fn prepare(dir: TempDir, consumer: &str, socket: PathBuf, mut command: std::process::Command) -> Self {
        let exe = std::env::current_exe().expect("the test's executable");
        dir.write(
            &format!("consumers/{consumer}.conf"),
            format!(
                "[Consumer]\nId={consumer}\nDisplayName=Process test\nExecutable={}\n\
                 DataDir=.local/share/{consumer}\n",
                exe.display()
            ),
        );
        std::fs::create_dir_all(dir.join("home")).expect("home");
        command
            .env("HOME", dir.join("home"))
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env("NETVFS_CONSUMERS_DIR", dir.join("consumers"))
            .env("NETVFS_ACCOUNTS_HELPER", dir.join("no-helper"))
            .env("NETVFS_BRIDGE_IDLE_EXIT_MS", "500")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            // zbus would find the host's session bus there.
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("NETVFS_FAKE_SEED")
            .stdin(std::process::Stdio::null());
        Self { dir, consumer: consumer.to_owned(), socket, command }
    }

    /// `bridge.conf` with `consent` for the consumer, as netvfs-ui writes it.
    pub fn with_consent(&mut self, consent: Consent) -> &mut Self {
        ConsentStore::new(self.consent_file()).set_consent(&self.consumer, consent).expect("bridge.conf");
        self
    }

    /// `bridge.conf`.
    #[must_use]
    pub fn consent_file(&self) -> PathBuf {
        self.dir.join("config/netvfs/bridge.conf")
    }

    /// The fake accounts helper `helper` (`netvfs-accounts-fake`) with
    /// account 1, and the fake backend's server set up for its empty
    /// secret.
    pub fn with_fake_accounts(&mut self, helper: &std::path::Path) -> &mut Self {
        let table = self.dir.write("accounts", FAKE_ACCOUNTS);
        self.command.env("NETVFS_ACCOUNTS_HELPER", helper).env("NETVFS_FAKE_ACCOUNTS", table);
        self.with_files(&[])
    }

    /// The files of the fake backend's server (`NETVFS_FAKE_SEED`, design
    /// §4.1), (path, content). Also the server's credentials: user `user`
    /// with the empty secret of the fake helper's accounts (credentials id
    /// 0, secret optional). The seed format has no empty hex word; `-` is
    /// one that decodes to nothing (`QByteArray::fromHex` skips what is not
    /// a hex digit).
    pub fn with_files(&mut self, files: &[(&[u8], &[u8])]) -> &mut Self {
        let mut seed = String::from("credentials user -\n");
        for (path, content) in files {
            for word in ["file ", &hex(path), " ", &hex(content), "\n"] {
                seed.push_str(word);
            }
        }
        let seed = self.dir.write("seed", seed);
        self.command.env("NETVFS_FAKE_SEED", seed);
        self
    }

    /// The session bus at `address`.
    pub fn with_session_bus(&mut self, address: &str) -> &mut Self {
        self.command.env("DBUS_SESSION_BUS_ADDRESS", address);
        self
    }

    /// Starts the bridge, its stderr into [`BridgeRun::log`], and waits
    /// until it listens (`listen` called, not just `bind`).
    #[must_use]
    pub fn spawn(&mut self) -> crate::testutil::TestChild {
        let log = std::fs::File::create(self.dir.join("bridge.log")).expect("bridge.log");
        let mut child =
            crate::testutil::TestChild::spawn(self.command.stdout(std::process::Stdio::null()).stderr(log))
                .expect("netvfs-bridge starts");
        let end = Instant::now().checked_add(WAIT).expect("a deadline");
        while !crate::testutil::listening(&self.socket) {
            if let Some(status) = child.child().try_wait().expect("try_wait") {
                panic!("netvfs-bridge ended with {status} before it listened");
            }
            assert!(Instant::now() < end, "nothing listens at {}", self.socket.display());
            thread::sleep(Duration::from_millis(10));
        }
        child
    }

    /// A connected client that has not said Hello.
    pub async fn client(&self) -> Connection {
        netvfs_bridge_proto::connect(&self.socket).await.expect("connected")
    }

    /// What the bridge wrote to stderr so far.
    #[must_use]
    pub fn log(&self) -> String {
        std::fs::read(self.dir.join("bridge.log"))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().flat_map(|b| [b >> 4, b & 15]).filter_map(|d| char::from_digit(d.into(), 16)).collect()
}
