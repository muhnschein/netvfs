// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bridge core: one task on the runtime thread owning all bridge state, lock-free, fed by one channel of [`Event`]s.

mod admin;
mod drives;
mod files;
mod jobs;
pub mod nearby;
pub mod questions;
pub mod quota;
pub mod states;

use crate::accounts::helper::HelperDirectory;
use crate::accounts::watch::AccountChanges;
use crate::accounts::{AccountDirectory, AccountLocation, Attention, FilesAccess};
use crate::config::{ConsumerInfo, Env};
use crate::consent::{Consent, ConsentStore, ConsentWatcher};
use crate::drives::DriveSource;
use crate::drives::udisks::UDisks;
use crate::ffi::{Conn, Ffi, ParsedUrl};
use crate::handoff::{self, Handoff, HandoffCall, Launcher, SessionBusLauncher};
use crate::jobs::JobOutcome;
use crate::locations::book::LocationBook;
use crate::locations::connector::{Connector, QUESTION_TIMEOUT};
use crate::locations::copyjobs::{CopyId, CopyJobs};
use crate::locations::knownhosts::KnownHosts;
use crate::locations::pool::{CONNECTION_IDLE, PoolSet};
use crate::locations::spec::LocationSpec;
use crate::locations::state::StateSignal;
use crate::locations::worker::{Turn, Work, WorkerId};
use crate::locations::{Answer, AskId, CancelToken, TaskContext, WorkerEvent, WorkerEvents};
use crate::peer::PeerChecker;
use crate::prompt::{ConsentPrompt, NotificationPrompt, PromptEvent};
use crate::server::{self, Call, ListenAddress, Listener, OutSignal, Outbox, Reply, ReplyTo, SessionId};
use crate::status::Status;
use admin::Waiter;
use drives::DriveCall;
use jobs::TransferCall;
use nearby::{FfiNearby, Nearby, NearbySource};
use netvfs_bridge_proto::limits::POOL_PER_HOST;
use netvfs_bridge_proto::{Lane, WireNearby};
use questions::QuestionBroker;
use quota::Quota;
use states::{StateReport, States};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// How often idle connections are closed and finished ones reaped.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// What the bridge of one consumer runs with.
#[derive(Debug, Clone)]
pub struct Config {
    /// The consumer.
    pub consumer: ConsumerInfo,
    /// `bridge.conf`.
    pub consent_file: PathBuf,
    /// The consumer's known_hosts.
    pub known_hosts_file: PathBuf,
    /// `handoff.conf`.
    pub handoff_config: PathBuf,
    /// The idle exit.
    pub idle_exit: Duration,
    /// Pooled connections without work are closed after this.
    pub connection_idle: Duration,
    /// How long a question waits for its answer.
    pub question_timeout: Duration,
}

impl Config {
    /// The configuration of `consumer` in `env`.
    #[must_use]
    pub fn new(env: &Env, consumer: ConsumerInfo) -> Self {
        Self {
            consent_file: env.consent_file(),
            known_hosts_file: env.known_hosts_file(&consumer.id),
            handoff_config: PathBuf::from(handoff::DEFAULT_CONFIG),
            idle_exit: Duration::from_millis(env.idle_exit_ms()),
            connection_idle: CONNECTION_IDLE,
            question_timeout: QUESTION_TIMEOUT,
            consumer,
        }
    }
}

/// A future of the runtime thread (not `Send`).
pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// [`AccountDirectory`] as a trait object.
pub trait Directory {
    /// [`AccountDirectory::list`].
    fn list(&self) -> LocalFuture<'_, Vec<AccountLocation>>;
    /// [`AccountDirectory::files`].
    fn files(&self, id: i32) -> LocalFuture<'_, Result<FilesAccess, Status>>;
    /// [`AccountDirectory::set_attention`].
    fn set_attention<'a>(&'a self, id: i32, attention: Attention, pin: &'a str) -> LocalFuture<'a, ()>;
}

impl<A: AccountDirectory> Directory for A {
    fn list(&self) -> LocalFuture<'_, Vec<AccountLocation>> {
        Box::pin(AccountDirectory::list(self))
    }

    fn files(&self, id: i32) -> LocalFuture<'_, Result<FilesAccess, Status>> {
        Box::pin(AccountDirectory::files(self, id))
    }

    fn set_attention<'a>(&'a self, id: i32, attention: Attention, pin: &'a str) -> LocalFuture<'a, ()> {
        Box::pin(AccountDirectory::set_attention(self, id, attention, pin))
    }
}

/// What the core talks to besides the backends, made on the runtime thread.
pub struct Services {
    /// The accounts.
    pub accounts: Rc<dyn Directory>,
    /// The consent question.
    pub prompt: Box<dyn ConsentPrompt>,
    /// The discovery of nearby servers.
    pub nearby: Box<dyn NearbySource>,
    /// Sends the settings handoff calls.
    pub launcher: Box<dyn Launcher>,
    /// The memory cards and USB drives.
    pub drives: Rc<dyn DriveSource>,
}

impl fmt::Debug for Services {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Services").field("prompt_shown", &self.prompt.is_shown()).finish_non_exhaustive()
    }
}

/// Makes the [`Services`] on the runtime thread, once the core's channel exists ([`CoreLink`]).
pub type MakeServices = Box<dyn FnOnce(CoreLink) -> LocalFuture<'static, Services> + Send>;

/// Parses `ConnectAdHoc` URLs; `None` falls through to the C ABI.
pub type UrlOverride = Arc<dyn Fn(&str) -> Option<ParsedUrl> + Send + Sync>;

/// The injectable dependencies of [`serve`](crate::serve).
pub struct Deps {
    /// The C ABI (loaded and `init`ed on the main thread).
    pub ffi: Ffi,
    /// Where to listen.
    pub listen: ListenAddress,
    /// The accounts, the prompt, the discovery and the handoff launcher.
    pub services: MakeServices,
    /// URLs parsed before the C ABI sees them.
    pub url_override: Option<UrlOverride>,
}

impl fmt::Debug for Deps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deps")
            .field("ffi", &self.ffi)
            .field("listen", &self.listen)
            .field("url_override", &self.url_override.is_some())
            .finish_non_exhaustive()
    }
}

impl Deps {
    /// The bridge's own.
    #[must_use]
    pub fn system(ffi: Ffi, listen: ListenAddress, env: &Env) -> Self {
        let helper = env.accounts_helper();
        let services: MakeServices = Box::new(move |link| Box::pin(system_services(ffi, helper, link)));
        Self { ffi, listen, services, url_override: None }
    }
}

async fn session_bus() -> Option<zbus::Connection> {
    zbus::Connection::session()
        .await
        .inspect_err(|e| crate::log::warning(format_args!("No session bus: {e}")))
        .ok()
}

async fn system_services(ffi: Ffi, helper: PathBuf, link: CoreLink) -> Services {
    let bus = session_bus().await;
    let mut changes = AccountChanges::subscribe(bus.as_ref()).await;
    let changed = link.clone();
    tokio::task::spawn_local(async move {
        loop {
            changes.next().await;
            if !changed.accounts_changed() {
                break;
            }
        }
    });
    let answers = link.clone();
    let drives_changed = link.clone();
    Services {
        accounts: Rc::new(HelperDirectory::new(helper)),
        prompt: Box::new(NotificationPrompt::start(bus.clone(), move |e| {
            // False once the core has stopped: nobody asks any more.
            let _told = answers.prompt(e);
        })),
        nearby: Box::new(FfiNearby::new(ffi, link)),
        launcher: Box::new(SessionBusLauncher::new(bus)),
        drives: Rc::new(UDisks::system(move || drives_changed.drives_changed())),
    }
}

/// The core's internal counters, for tests ([`CoreLink::probe`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Connected sessions.
    pub sessions: usize,
    /// Requests in flight.
    pub requests: usize,
    /// Calls, `List` requests and jobs the sessions still track (their cancel flags and reply slots).
    pub ops: usize,
    /// Open read handles.
    pub handles: usize,
    /// Running jobs.
    pub jobs: usize,
    /// Pending questions.
    pub questions: usize,
    /// Running copy jobs.
    pub copy_jobs: usize,
    /// Pools of locations.
    pub pools: usize,
    /// Whether the discovery runs.
    pub discovering: bool,
}

#[derive(Debug)]
pub(crate) enum Event {
    Server(server::Event),
    Worker(WorkerEvent),
    Done { sid: SessionId, op: u64, result: Result<Reply, Status> },
    AdHocDone { sid: SessionId, op: u64, loc: String, result: Result<(), Status> },
    ListDone { sid: SessionId, request: u32, result: Result<(), Status> },
    Opened { sid: SessionId, op: u64, loc: String, opened: Result<(WorkerId, u32, i64), Status> },
    Progress { sid: SessionId, job: u32, done: i64, total: i64 },
    JobFinished { sid: SessionId, job: u32, outcome: JobOutcome },
    ConsentFile,
    ConsentStored(Consent),
    Prompt(PromptEvent),
    AccountsChanged,
    AccountsListed { generation: u64, accounts: Vec<AccountLocation> },
    Nearby(Vec<WireNearby>),
    ConnectionStates,
    DrivesChanged,
    Probe(oneshot::Sender<Counters>),
    Shutdown,
}

/// A way into the core from anywhere.
#[derive(Clone)]
pub struct CoreLink(mpsc::UnboundedSender<Event>);

impl fmt::Debug for CoreLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLink").field("closed", &self.0.is_closed()).finish()
    }
}

impl CoreLink {
    fn send(&self, event: Event) -> bool {
        self.0.send(event).is_ok()
    }

    /// The consent question was answered or dismissed.
    #[must_use = "false: the core has stopped"]
    pub fn prompt(&self, event: PromptEvent) -> bool {
        self.send(Event::Prompt(event))
    }

    /// The accounts may have changed.
    #[must_use = "false: the core has stopped"]
    pub fn accounts_changed(&self) -> bool {
        self.send(Event::AccountsChanged)
    }

    /// The discovery's current list of nearby servers.
    #[must_use = "false: the core has stopped"]
    pub fn nearby(&self, services: Vec<WireNearby>) -> bool {
        self.send(Event::Nearby(services))
    }

    /// What `ListDrives` lists changed.
    #[must_use = "false: the core has stopped"]
    pub fn drives_changed(&self) -> bool {
        self.send(Event::DrivesChanged)
    }

    /// Stops serving.
    #[must_use = "false: the core has stopped"]
    pub fn shutdown(&self) -> bool {
        self.send(Event::Shutdown)
    }

    /// The core's counters.
    pub async fn probe(&self) -> Option<Counters> {
        let (tx, rx) = oneshot::channel();
        if !self.send(Event::Probe(tx)) {
            return None;
        }
        rx.await.ok()
    }
}

struct Op {
    reply: Option<ReplyTo>,
    cancel: CancelToken,
}

#[derive(Debug, Clone)]
struct HandleRef {
    loc: String,
    worker: WorkerId,
    handle: u32,
}

struct Session {
    outbox: Outbox,
    hello: bool,
    canceled: bool,
    next_op: u64,
    next_public: u32,
    next_handle: u32,
    ops: HashMap<u64, Op>,
    public: HashMap<u32, u64>,
    handles: HashMap<u32, HandleRef>,
}

impl Session {
    fn new(outbox: Outbox) -> Self {
        Self {
            outbox,
            hello: false,
            canceled: false,
            next_op: 1,
            next_public: 1,
            next_handle: 1,
            ops: HashMap::new(),
            public: HashMap::new(),
            handles: HashMap::new(),
        }
    }

    fn new_op(&mut self, reply: Option<ReplyTo>, public: bool) -> (u64, u32, CancelToken) {
        let op = self.next_op;
        self.next_op = self.next_op.saturating_add(1);
        let cancel: CancelToken = Arc::new(AtomicBool::new(false));
        let id = if public {
            let id = self.next_public;
            self.next_public = self.next_public.saturating_add(1);
            self.public.insert(id, op);
            id
        } else {
            0
        };
        self.ops.insert(op, Op { reply, cancel: Arc::clone(&cancel) });
        (op, id, cancel)
    }

    fn end_public(&mut self, id: u32) {
        if let Some(op) = self.public.remove(&id) {
            self.ops.remove(&op);
        }
    }

    fn signal(&self, signal: &OutSignal) {
        if !self.canceled {
            // False only when the session is closed: nothing to do.
            let _sent = self.outbox.signal(signal);
        }
    }
}

struct DynLauncher(Box<dyn Launcher>);

impl Launcher for DynLauncher {
    fn launch(&self, call: &HandoffCall) -> Result<(), Status> {
        self.0.launch(call)
    }
}

pub(crate) struct Core {
    config: Config,
    ffi: Ffi,
    tx: mpsc::UnboundedSender<Event>,
    consent_store: ConsentStore,
    consent: Consent,
    prompt: Box<dyn ConsentPrompt>,
    accounts: Rc<dyn Directory>,
    accounts_generation: u64,
    drives: Rc<dyn DriveSource>,
    handoff: Handoff<DynLauncher>,
    known_hosts: Arc<KnownHosts>,
    book: LocationBook<Connector>,
    copy_jobs: CopyJobs<Connector>,
    copy_owners: HashMap<CopyId, (SessionId, u32)>,
    quota: Quota,
    questions: QuestionBroker<Waiter>,
    asks: HashMap<AskId, String>,
    nearby: Nearby,
    states: StateReport,
    state_signal: StateSignal,
    sessions: BTreeMap<SessionId, Session>,
    idle_deadline: Option<Instant>,
    consent_writes: usize,
    url_override: Option<UrlOverride>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

pub(crate) async fn run(config: Config, deps: Deps) -> ExitCode {
    let socket = match server::listener::bind(&deps.listen) {
        Ok(socket) => socket,
        Err(status) => {
            crate::log::critical(format_args!("{}", status.message));
            return ExitCode::FAILURE;
        }
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server_tx = tx.clone();
    let sink = server::EventSink::new(move |event| {
        // A closed channel: the core has stopped.
        drop(server_tx.send(Event::Server(event)));
    });
    let listener = Listener::new(socket, PeerChecker::new(&config.consumer.executable), sink);
    let accepting = tokio::task::spawn_local(async move {
        let error = listener.serve().await;
        crate::log::critical(format_args!("The listening socket failed: {error}"));
    });
    crate::log::debug(format_args!("Listening on {:?}", deps.listen));
    let services = (deps.services)(CoreLink(tx.clone())).await;
    watch_consent_file(&config, &tx);
    let mut core = Core::new(config, deps.ffi, tx, services);
    core.url_override = deps.url_override;
    let accounts = core.accounts.list().await;
    core.set_accounts(&accounts);
    core.run(&mut rx).await;
    accepting.abort();
    drop(core);
    ExitCode::SUCCESS
}

fn watch_consent_file(config: &Config, tx: &mpsc::UnboundedSender<Event>) {
    match ConsentWatcher::new(&config.consent_file) {
        Ok(mut watcher) => {
            let tx = tx.clone();
            tokio::task::spawn_local(async move {
                loop {
                    if let Err(e) = watcher.changed().await {
                        crate::log::warning(format_args!("Consent changes are not seen any more: {e}"));
                        break;
                    }
                    if tx.send(Event::ConsentFile).is_err() {
                        break;
                    }
                }
            });
        }
        Err(e) => crate::log::warning(format_args!("Consent changes are seen only after a restart: {e}")),
    }
}

impl Core {
    fn new(config: Config, ffi: Ffi, tx: mpsc::UnboundedSender<Event>, services: Services) -> Self {
        let worker_tx = tx.clone();
        let events = WorkerEvents::new(move |event| {
            drop(worker_tx.send(Event::Worker(event)));
        });
        let known_hosts = Arc::new(KnownHosts::new(&config.known_hosts_file));
        let pins: Arc<dyn crate::locations::connector::PinStore> = Arc::<KnownHosts>::clone(&known_hosts);
        let connector = Arc::new(Connector::new(ffi, pins, events.clone(), config.question_timeout));
        let consent_store = ConsentStore::new(&config.consent_file);
        let consent = consent_store.consent(&config.consumer.id);
        let state_tx = tx.clone();
        let state_signal = StateSignal::new(move || {
            // A closed channel: the core has stopped.
            drop(state_tx.send(Event::ConnectionStates));
        });
        let pools = PoolSet::new(Arc::clone(&connector), POOL_PER_HOST).with_signal(state_signal.clone());
        Self {
            ffi,
            tx,
            consent_store,
            consent,
            prompt: services.prompt,
            accounts: services.accounts,
            accounts_generation: 0,
            drives: services.drives,
            handoff: Handoff::new(&config.handoff_config, DynLauncher(services.launcher)),
            known_hosts,
            book: LocationBook::new(pools),
            copy_jobs: CopyJobs::new(connector, events),
            copy_owners: HashMap::new(),
            quota: Quota::default(),
            questions: QuestionBroker::default(),
            asks: HashMap::new(),
            nearby: Nearby::new(services.nearby),
            states: StateReport::default(),
            state_signal,
            sessions: BTreeMap::new(),
            idle_deadline: None,
            consent_writes: 0,
            url_override: None,
            config,
        }
    }

    async fn run(&mut self, rx: &mut mpsc::UnboundedReceiver<Event>) {
        let start = Instant::now();
        let mut maintenance = tokio::time::interval_at(
            start.checked_add(MAINTENANCE_INTERVAL).unwrap_or(start),
            MAINTENANCE_INTERVAL,
        );
        loop {
            self.update_idle();
            let (idle, nearby, states) = (self.idle_deadline, self.nearby.due(), self.states.due());
            let flow = tokio::select! {
                event = rx.recv() => match event {
                    Some(event) => self.handle(event),
                    None => Flow::Stop,
                },
                () = sleep_until(idle) => self.idle_timeout(),
                _ = maintenance.tick() => {
                    self.book.maintain(Instant::now().into_std(), self.config.connection_idle);
                    Flow::Continue
                }
                () = sleep_until(nearby) => {
                    self.report_nearby();
                    Flow::Continue
                }
                () = sleep_until(states) => {
                    self.report_states();
                    Flow::Continue
                }
            };
            if flow == Flow::Stop {
                break;
            }
        }
    }

    fn handle(&mut self, event: Event) -> Flow {
        match event {
            Event::Server(event) => self.on_server(event),
            Event::Worker(event) => self.on_worker(event),
            Event::Done { sid, op, result } => self.on_done(sid, op, result),
            Event::AdHocDone { sid, op, loc, result } => self.on_ad_hoc_done(sid, op, &loc, result),
            Event::ListDone { sid, request, result } => self.on_list_done(sid, request, result),
            Event::Opened { sid, op, loc, opened } => self.on_opened(sid, op, loc, opened),
            Event::Progress { sid, job, done, total } => self.on_progress(sid, job, done, total),
            Event::JobFinished { sid, job, outcome } => {
                self.quota.release_job();
                self.finish_job(sid, job, outcome);
            }
            Event::ConsentFile => self.reload_consent(),
            Event::ConsentStored(consent) => self.on_consent_stored(consent),
            Event::Prompt(event) => self.on_prompt(event),
            Event::AccountsChanged => self.refresh_accounts(),
            Event::AccountsListed { generation, accounts } => {
                if generation == self.accounts_generation {
                    self.set_accounts(&accounts);
                    if self.consent == Consent::Granted {
                        self.locations_changed();
                    }
                }
            }
            Event::Nearby(services) => self.nearby.changed(services, Instant::now()),
            Event::ConnectionStates => self.states.changed(Instant::now()),
            Event::DrivesChanged => self.broadcast(&OutSignal::DrivesChanged),
            Event::Probe(tx) => drop(tx.send(self.counters())),
            Event::Shutdown => return Flow::Stop,
        }
        Flow::Continue
    }

    fn counters(&self) -> Counters {
        Counters {
            sessions: self.sessions.len(),
            requests: self.quota.active_requests(),
            ops: self.sessions.values().map(|s| s.ops.len()).sum(),
            handles: self.quota.open_handles(),
            jobs: self.quota.running_jobs(),
            questions: self.questions.pending(),
            copy_jobs: self.copy_jobs.len(),
            pools: self.book.pools().iter().count(),
            discovering: self.nearby.is_running(),
        }
    }

    fn is_idle(&self) -> bool {
        self.sessions.is_empty()
            && self.quota.running_jobs() == 0
            && self.quota.active_requests() == 0
            && self.copy_jobs.is_idle()
            && !self.prompt.is_shown()
            && self.consent_writes == 0
    }

    fn update_idle(&mut self) {
        if !self.is_idle() {
            self.idle_deadline = None;
        } else if self.idle_deadline.is_none() {
            self.idle_deadline = Instant::now().checked_add(self.config.idle_exit);
        }
    }

    fn idle_timeout(&mut self) -> Flow {
        self.idle_deadline = None;
        if self.is_idle() {
            crate::log::debug(format_args!("Idle: exiting"));
            return Flow::Stop;
        }
        Flow::Continue
    }

    fn on_server(&mut self, event: server::Event) {
        match event {
            server::Event::Accepted { sid, outbox } => {
                crate::log::debug(format_args!("Client {sid} connected"));
                self.sessions.insert(sid, Session::new(outbox));
            }
            server::Event::Call { sid, reply, call } => self.on_call(sid, reply, call),
            server::Event::Closed { sid } => {
                self.cancel_session(sid);
                self.sessions.remove(&sid);
                crate::log::debug(format_args!("Client {sid} disconnected"));
            }
            server::Event::Refused { reason } => {
                crate::log::warning(format_args!("Refused a connection: {}", reason.message));
            }
        }
    }

    fn on_call(&mut self, sid: SessionId, reply: ReplyTo, call: Call) {
        if !self.sessions.contains_key(&sid) {
            return;
        }
        if call.needs_consent() && self.consent != Consent::Granted {
            reply.fail(&crate::locations::book::no_consent());
            return;
        }
        let lane = call.lane();
        match call {
            Call::Hello { client } => self.on_hello(sid, reply, &client),
            Call::GetConsent => self.on_get_consent(reply),
            Call::RequestConsent => self.on_request_consent(reply),
            Call::GetFeatures => self.on_get_features(reply),
            Call::ListLocations => self.on_list_locations(reply),
            Call::Capabilities { loc } => self.on_capabilities(sid, reply, &loc, lane),
            Call::Disconnect { loc } => self.on_disconnect(reply, &loc),
            Call::ConnectAdHoc { url, secret, opts } => {
                self.on_connect_ad_hoc(sid, reply, &url, secret, opts);
            }
            Call::ForgetAdHoc { loc } => self.on_forget_ad_hoc(reply, &loc),
            Call::Discover { on } => self.on_discover(sid, reply, on),
            Call::Cancel { id } => self.on_cancel(sid, reply, id),
            Call::Answer { id, accept, answers } => self.on_answer(sid, reply, &id, accept, answers),
            Call::OpenAccountSettings { loc } => self.on_open_account_settings(reply, &loc),
            Call::AddAccount { provider } => self.on_add_account(reply, &provider),
            Call::OpenStorageSettings => self.on_open_storage_settings(reply),
            Call::ListDrives => self.on_drive_call(sid, reply, DriveCall::List),
            Call::Mount { drive } => self.on_drive_call(sid, reply, DriveCall::Mount(drive)),
            Call::Unmount { drive } => self.on_drive_call(sid, reply, DriveCall::Unmount(drive)),
            call => self.on_file_call(sid, reply, call, lane),
        }
    }

    fn on_file_call(&mut self, sid: SessionId, reply: ReplyTo, call: Call, lane: Lane) {
        match call {
            Call::List { loc, dir, lane, batch } => self.on_list(sid, reply, &loc, dir, lane, batch),
            Call::Stat { loc, path, follow, lane } => self.on_stat(sid, reply, &loc, path, follow, lane),
            Call::ReadLink { loc, path } => self.on_read_link(sid, reply, &loc, path, lane),
            Call::SpaceInfo { loc, path } => self.on_space_info(sid, reply, &loc, path, lane),
            Call::Checksum { loc, path, algorithm } => {
                self.on_checksum(sid, reply, &loc, path, algorithm, lane);
            }
            Call::MakeDir { loc, path, exclusive } => {
                self.run_empty(sid, reply, &loc, lane, move |c| c.make_dir(path.as_bytes(), exclusive));
            }
            Call::RemoveFile { loc, path } => {
                self.run_empty(sid, reply, &loc, lane, move |c| c.remove_file(path.as_bytes()));
            }
            Call::RemoveDir { loc, path } => {
                self.run_empty(sid, reply, &loc, lane, move |c| c.remove_dir(path.as_bytes()));
            }
            Call::Rename { loc, from, to, replace } => {
                self.run_empty(sid, reply, &loc, lane, move |c| {
                    c.rename(from.as_bytes(), to.as_bytes(), replace)
                });
            }
            Call::SetAttributes { loc, path, changes } => {
                self.on_set_attributes(sid, reply, &loc, path, changes, lane);
            }
            Call::MakeSymlink { loc, target, link } => {
                self.run_empty(sid, reply, &loc, lane, move |c| c.make_symlink(&target, link.as_bytes()));
            }
            Call::MakeHardlink { loc, existing, link } => {
                self.run_empty(sid, reply, &loc, lane, move |c| {
                    c.make_hardlink(existing.as_bytes(), link.as_bytes())
                });
            }
            Call::ServerCopy { loc, from, to, opts } => {
                self.on_server_copy(sid, reply, &loc, (from, to), opts, lane);
            }
            Call::OpenRead { loc, path, lane } => self.on_open_read(sid, reply, &loc, path, lane),
            Call::Read { handle, offset, max } => self.on_read(sid, reply, handle, offset, max),
            Call::ReadAhead { handle, offset, bytes } => {
                self.on_read_ahead(sid, reply, handle, offset, bytes);
            }
            Call::Close { handle } => self.on_close(sid, reply, handle),
            Call::Upload { loc, path, fd, opts, lane } => {
                self.on_transfer(sid, reply, TransferCall { loc, path, fd, opts, lane, upload: true });
            }
            Call::Download { loc, path, fd, opts, lane } => {
                self.on_transfer(sid, reply, TransferCall { loc, path, fd, opts, lane, upload: false });
            }
            Call::CopyAcross { loc, path, dest_loc, dest_path, opts } => {
                self.on_copy_across(sid, reply, (&loc, path), (&dest_loc, dest_path), opts);
            }
            Call::RemoveTree { loc, path } => self.on_remove_tree(sid, reply, (&loc, lane), path),
            Call::Walk { loc, path, opts } => self.on_walk(sid, reply, (&loc, lane), path, opts),
            other => reply.fail(&Status::new(
                netvfs_bridge_proto::ErrorName::Internal,
                format!("{} has no handler", other.name()),
            )),
        }
    }

    fn cancel_session(&mut self, sid: SessionId) {
        let Some(session) = self.sessions.get_mut(&sid) else { return };
        if session.canceled {
            return;
        }
        session.canceled = true;
        for op in session.ops.values() {
            op.cancel.store(true, Ordering::Release);
        }
        // Their replies go nowhere: the session is closed.
        let ops = std::mem::take(&mut session.ops);
        session.public.clear();
        let handles = std::mem::take(&mut session.handles);
        drop(ops);
        for h in handles.into_values() {
            self.quota.release_handle();
            self.book.close_worker_handle(&h.loc, h.worker, h.handle);
        }
        for waiter in self.questions.drop_session(sid) {
            self.resolve(waiter, None);
        }
        self.nearby.set_discovering(sid, false, Instant::now());
        self.kick_all();
    }

    fn kick_all(&mut self) {
        self.book.kick();
        self.copy_jobs.kick();
    }

    fn broadcast(&self, signal: &OutSignal) {
        for session in self.sessions.values().filter(|s| s.hello) {
            session.signal(signal);
        }
    }

    fn locations_changed(&mut self) {
        self.broadcast(&OutSignal::LocationsChanged);
        let states = self.connection_states();
        self.states.announced(states);
    }

    fn connection_states(&self) -> States {
        if self.consent == Consent::Granted { self.book.states() } else { States::new() }
    }

    fn report_states(&mut self) {
        // Whether a change woke the core already does not matter: `ListLocations` may have asked for the look.
        let _woken = self.state_signal.take();
        let states = self.connection_states();
        if self.states.check(states) && self.consent == Consent::Granted {
            self.broadcast(&OutSignal::LocationsChanged);
        }
    }

    fn session(&mut self, sid: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&sid)
    }

    fn on_done(&mut self, sid: SessionId, op: u64, result: Result<Reply, Status>) {
        self.quota.release_request();
        let Some(reply) = self.take_reply(sid, op) else { return };
        match result {
            Ok(r) => reply.ok(&r),
            Err(status) => reply.fail(&status),
        }
    }

    fn take_reply(&mut self, sid: SessionId, op: u64) -> Option<ReplyTo> {
        self.session(sid).and_then(|s| s.ops.remove(&op)).and_then(|op| op.reply)
    }

    fn on_progress(&mut self, sid: SessionId, job: u32, done: i64, total: i64) {
        if let Some(session) = self.sessions.get(&sid)
            && session.public.contains_key(&job)
        {
            session.signal(&OutSignal::JobProgress { job, done, total });
        }
    }

    fn finish_job(&mut self, sid: SessionId, job: u32, outcome: JobOutcome) {
        let Some(session) = self.session(sid) else { return };
        session.end_public(job);
        session.signal(&OutSignal::JobFinished { job, result: outcome.result, extra: outcome.extra });
    }

    fn on_worker(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Ask { ask, session, kind, details, answer } => {
                let id = self.questions.ask(session, Waiter::Worker { ask, answer });
                self.asks.insert(ask, id.clone());
                self.emit_question(session, &id, kind, details);
            }
            WorkerEvent::CancelQuestion(ask) => {
                if let Some(id) = self.asks.remove(&ask)
                    && let Some(waiter) = self.questions.cancel(&id)
                {
                    self.resolve(waiter, None);
                }
            }
            WorkerEvent::FetchAccount { account_id, reply } => {
                let accounts = Rc::clone(&self.accounts);
                tokio::task::spawn_local(async move {
                    let access = accounts.files(account_id).await.map(Into::into);
                    // The worker may have stopped waiting.
                    drop(reply.send(access));
                });
            }
            WorkerEvent::Attention { account_id, attention, pin } => {
                let accounts = Rc::clone(&self.accounts);
                let tx = self.tx.clone();
                tokio::task::spawn_local(async move {
                    accounts.set_attention(account_id, attention, &pin).await;
                    drop(tx.send(Event::AccountsChanged));
                });
            }
            WorkerEvent::CopyDone { id, result } => {
                self.copy_jobs.finish(id, self.book.pools_mut());
                self.quota.release_job();
                if let Some((sid, job)) = self.copy_owners.remove(&id) {
                    // copy_across reports its own Canceled.
                    self.finish_job(sid, job, JobOutcome { result, extra: HashMap::new() });
                }
            }
            WorkerEvent::Warning(text) => crate::log::warning(format_args!("{text}")),
        }
    }

    fn emit_question(
        &mut self,
        sid: SessionId,
        id: &str,
        kind: &str,
        details: HashMap<String, zbus::zvariant::OwnedValue>,
    ) {
        let sent = self.sessions.get(&sid).is_some_and(|s| !s.canceled)
            && self.sessions.get(&sid).is_some_and(|s| {
                s.outbox.signal(&OutSignal::Question { id: id.to_owned(), kind: kind.to_owned(), details })
            });
        if !sent && let Some(waiter) = self.questions.cancel(id) {
            self.resolve(waiter, None);
        }
    }

    fn resolve(&mut self, waiter: Waiter, answer: Option<Answer>) {
        match waiter {
            Waiter::Worker { ask, answer: tx } => {
                self.asks.remove(&ask);
                // The worker may have stopped waiting.
                drop(tx.send(answer));
            }
            Waiter::Insecure { sid, pending, reply } => {
                self.insecure_answered(sid, *pending, reply, answer.is_some_and(|a| a.accept));
            }
        }
    }

    fn refresh_accounts(&mut self) {
        self.accounts_generation = self.accounts_generation.wrapping_add(1);
        let generation = self.accounts_generation;
        let (accounts, tx) = (Rc::clone(&self.accounts), self.tx.clone());
        tokio::task::spawn_local(async move {
            let accounts = accounts.list().await;
            drop(tx.send(Event::AccountsListed { generation, accounts }));
        });
    }

    fn set_accounts(&mut self, accounts: &[AccountLocation]) {
        self.book.set_accounts(accounts.iter().map(account_spec).collect());
        let states = self.connection_states();
        self.states.announced(states);
    }

    fn pool_for(&mut self, loc: &str) -> Result<Arc<LocationSpec>, Status> {
        let granted = self.consent == Consent::Granted;
        let ffi = self.ffi;
        self.book.ensure_pool(loc, granted, |p| ffi.provider_available(p)).map(Arc::clone)
    }

    fn run_request(
        &mut self,
        sid: SessionId,
        reply: ReplyTo,
        loc: &str,
        lane: Lane,
        body: impl FnOnce(&mut Conn) -> Result<Reply, Status> + Send + 'static,
    ) {
        if let Err(status) = self.pool_for(loc) {
            reply.fail(&status);
            return;
        }
        let Some((op, cancel)) = self.start_request(sid, reply) else { return };
        let tx = self.tx.clone();
        let work: Work<Connector> = Box::new(move |turn: Turn<'_, Connector>| {
            let result = turn.ready.and_then(body);
            let kept = result.as_ref().map(|_| ()).map_err(Status::clone);
            drop(tx.send(Event::Done { sid, op, result }));
            kept
        });
        self.book.submit(loc, lane, TaskContext::new(sid, cancel), work);
    }

    fn start_request(&mut self, sid: SessionId, reply: ReplyTo) -> Option<(u64, CancelToken)> {
        if !self.quota.acquire_request() {
            reply.fail(&quota::too_many("Too many requests"));
            return None;
        }
        let Some(session) = self.session(sid) else {
            self.quota.release_request();
            return None;
        };
        let (op, _, cancel) = session.new_op(Some(reply), false);
        Some((op, cancel))
    }

    fn report_nearby(&mut self) {
        let (to, services) = self.nearby.report();
        if self.consent != Consent::Granted {
            return;
        }
        for sid in to {
            if let Some(session) = self.sessions.get(&sid) {
                session.signal(&OutSignal::NearbyChanged(services.clone()));
            }
        }
    }
}

fn account_spec(a: &AccountLocation) -> LocationSpec {
    LocationSpec::account(
        a.account_id,
        a.provider.clone(),
        a.display_name.clone(),
        a.params.to_ffi(),
        a.files_root.clone(),
        a.attention,
    )
}
