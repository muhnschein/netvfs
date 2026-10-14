// SPDX-License-Identifier: LGPL-2.1-or-later
//! One backend connection on its own std thread (C-8, port of
//! `worker.cpp`, design §3.3).
//!
//! Work items run in order. The connection is created
//! ([`Backend::create`], `conn_new`) and established
//! ([`Backend::establish`], the connector) lazily by the first item. An
//! item that ends with `Canceled`, `ConnectionLost`, `Timeout` or
//! `NetworkUnreachable`, or whose cancel flag is set, drops the connection
//! and its read handles, so that the next item starts clean (XB-13);
//! otherwise the connection's cancel state is reset. [`Worker::stop`]
//! cancels, has every queued item end with `Canceled` and ends the thread;
//! [`Worker::finished`] says when it has.
//!
//! Shared with the core are only the queue and the connection's cancel
//! handle, under one mutex: a cancel never overlaps or follows the free of
//! the connection (T4), because the thread takes the handle out under it
//! first.

use super::spec::LocationSpec;
use super::{TaskContext, canceled};
use crate::Status;
use netvfs_bridge_proto::{ErrorName, Lane};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Instant;

/// The name of worker threads.
pub const THREAD_NAME: &str = "nvb-w";

/// What a worker needs of the backends: the production one is
/// [`Connector`](super::connector::Connector) over the C ABI; tests use a
/// fake. Called on the worker thread, except [`Backend::cancel`], which
/// any thread may call.
pub trait Backend: Send + Sync + 'static {
    /// A connection; owned by the thread that created it.
    type Conn: 'static;
    /// A read handle of a connection; owned by the same thread.
    type Handle: 'static;
    /// What cancels a connection's running call from another thread.
    type Cancel: Send + 'static;

    /// A new, unconnected connection for `spec` (`conn_new`).
    ///
    /// # Errors
    /// No backend for the provider (`Unsupported`), …
    fn create(&self, spec: &LocationSpec) -> Result<Self::Conn, Status>;

    /// The cancel handle of `conn`.
    fn cancel_handle(&self, conn: &Self::Conn) -> Self::Cancel;

    /// Cancels the connection's running call (any thread).
    fn cancel(&self, handle: &Self::Cancel);

    /// Connects, checks the identity and authenticates (C-7, XB-14) for
    /// `task`'s request.
    ///
    /// # Errors
    /// The failure; the connection is then dropped.
    fn establish(&self, conn: &mut Self::Conn, spec: &LocationSpec, task: &TaskContext)
    -> Result<(), Status>;

    /// Makes the connection usable again after a cancel.
    fn reset_cancel(&self, conn: &mut Self::Conn);
}

/// A worker, unique in the process: what a read handle's owner is recorded
/// as (the C++ `Worker *`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId(pub u64);

impl WorkerId {
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// The read handles of a worker's connection (worker thread only), by
/// number from 1. They go before their connection does.
pub struct Handles<H> {
    map: BTreeMap<u32, H>,
    next: u32,
    count: Arc<AtomicUsize>,
}

impl<H> fmt::Debug for Handles<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handles")
            .field("open", &self.map.len())
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl<H> Handles<H> {
    /// An empty table whose size is mirrored into `count`.
    #[must_use]
    pub fn new(count: Arc<AtomicUsize>) -> Self {
        count.store(0, Ordering::Release);
        Self { map: BTreeMap::new(), next: 1, count }
    }

    fn mirror(&self) {
        self.count.store(self.map.len(), Ordering::Release);
    }

    /// Keeps `handle`; its number.
    pub fn add(&mut self, handle: H) -> u32 {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.map.insert(id, handle);
        self.mirror();
        id
    }

    /// The handle numbered `id`.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut H> {
        self.map.get_mut(&id)
    }

    /// Takes the handle numbered `id` out (dropping it closes it).
    pub fn remove(&mut self, id: u32) -> Option<H> {
        let handle = self.map.remove(&id);
        self.mirror();
        handle
    }

    /// Open handles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether none is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drops every handle.
    pub fn clear(&mut self) {
        self.map.clear();
        self.mirror();
    }
}

/// What a work item gets.
pub struct Turn<'a, B: Backend> {
    /// The established connection, or why there is none (establish failed,
    /// the item was canceled while queued, the worker is stopping).
    pub ready: Result<&'a mut B::Conn, Status>,
    /// The connection's read handles; `None` when the item ends without
    /// reaching a worker (canceled while pending in its pool).
    pub handles: Option<&'a mut Handles<B::Handle>>,
    /// The worker running the item; `None` as for `handles`.
    pub worker: Option<WorkerId>,
}

impl<B: Backend> fmt::Debug for Turn<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Turn")
            .field("ready", &self.ready.as_ref().map(|_| ()))
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
}

impl<B: Backend> Turn<'_, B> {
    /// The turn of an item that never reached a worker.
    #[must_use]
    pub const fn failed(status: Status) -> Self {
        Self { ready: Err(status), handles: None, worker: None }
    }
}

/// A work item: runs once on the worker thread (or, when it never gets
/// there, on the core's with [`Turn::failed`]) and returns its result,
/// which decides whether the connection is kept.
pub type Work<B> = Box<dyn for<'a> FnOnce(Turn<'a, B>) -> Result<(), Status> + Send>;

/// Whether a result drops the connection (`dropsConnection`).
#[must_use]
pub fn drops_connection(result: &Result<(), Status>) -> bool {
    result.as_ref().is_err_and(|s| {
        matches!(
            s.name,
            ErrorName::Canceled
                | ErrorName::ConnectionLost
                | ErrorName::Timeout
                | ErrorName::NetworkUnreachable
        )
    })
}

struct Item<B: Backend> {
    task: TaskContext,
    work: Work<B>,
}

struct State<B: Backend> {
    queue: VecDeque<Item<B>>,
    stopping: bool,
    running: bool,
    current: Option<super::CancelToken>,
    cancel: Option<B::Cancel>,
    last_activity: Instant,
}

struct Shared<B: Backend> {
    backend: Arc<B>,
    state: Mutex<State<B>>,
    wake: Condvar,
    finished: AtomicBool,
    handles: Arc<AtomicUsize>,
}

impl<B: Backend> Shared<B> {
    fn lock(&self) -> MutexGuard<'_, State<B>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One connection's thread (`Worker`). Dropping it stops the thread and
/// waits for it.
pub struct Worker<B: Backend> {
    id: WorkerId,
    lane: Lane,
    shared: Arc<Shared<B>>,
    thread: Option<JoinHandle<()>>,
}

impl<B: Backend> fmt::Debug for Worker<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker")
            .field("id", &self.id)
            .field("lane", &self.lane)
            .field("load", &self.load())
            .field("finished", &self.finished())
            .finish_non_exhaustive()
    }
}

impl<B: Backend> Worker<B> {
    /// Starts the thread of a connection to `spec` in `lane`.
    ///
    /// # Errors
    /// The thread could not be started.
    pub fn start(backend: Arc<B>, spec: Arc<LocationSpec>, lane: Lane) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            backend,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                stopping: false,
                running: false,
                current: None,
                cancel: None,
                last_activity: Instant::now(),
            }),
            wake: Condvar::new(),
            finished: AtomicBool::new(false),
            handles: Arc::new(AtomicUsize::new(0)),
        });
        let id = WorkerId::next();
        let theirs = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || run(&theirs, &spec, id))?;
        Ok(Self { id, lane, shared, thread: Some(thread) })
    }

    /// The worker's id.
    #[must_use]
    pub const fn id(&self) -> WorkerId {
        self.id
    }

    /// Its lane.
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }

    /// Queues `work` for `task`. Also while stopping: the item then ends
    /// with `Canceled`, so it is never lost.
    pub fn post(&self, task: TaskContext, work: Work<B>) {
        self.shared.lock().queue.push_back(Item { task, work });
        self.shared.wake.notify_all();
    }

    /// Cancels the running item's backend call if its cancel flag is set
    /// (after the core set flags).
    pub fn kick(&self) {
        let state = self.shared.lock();
        if state.current.as_ref().is_some_and(|c| c.load(Ordering::Acquire))
            && let Some(cancel) = state.cancel.as_ref()
        {
            self.shared.backend.cancel(cancel);
        }
    }

    /// Without waiting: cancels the running item and its backend call, has
    /// the queued items end with `Canceled`, and ends the thread.
    pub fn stop(&self) {
        let mut state = self.shared.lock();
        state.stopping = true;
        if let Some(current) = state.current.as_ref() {
            current.store(true, Ordering::Release);
        }
        if let Some(cancel) = state.cancel.as_ref() {
            self.shared.backend.cancel(cancel);
        }
        drop(state);
        self.shared.wake.notify_all();
    }

    /// Whether the thread has ended (its connection is closed).
    #[must_use]
    pub fn finished(&self) -> bool {
        self.shared.finished.load(Ordering::Acquire)
    }

    /// Queued items plus the running one.
    #[must_use]
    pub fn load(&self) -> usize {
        let state = self.shared.lock();
        state.queue.len().saturating_add(usize::from(state.running))
    }

    /// When the last item ended (or the worker started); `None` while
    /// busy.
    #[must_use]
    pub fn idle_since(&self) -> Option<Instant> {
        let state = self.shared.lock();
        (!state.running && state.queue.is_empty()).then_some(state.last_activity)
    }

    /// Read handles open on the connection.
    #[must_use]
    pub fn open_handles(&self) -> usize {
        self.shared.handles.load(Ordering::Acquire)
    }
}

impl<B: Backend> Drop for Worker<B> {
    fn drop(&mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            // A work item that panicked has aborted the process already
            // (panic = "abort"); nothing to report here.
            drop(thread.join());
        }
        // Items posted after the thread's last look at the queue: they end
        // here, never lost.
        let left = std::mem::take(&mut self.shared.lock().queue);
        for item in left {
            drop((item.work)(Turn::failed(canceled())));
        }
    }
}

/// The thread's connection and handles.
struct Local<B: Backend> {
    conn: Option<B::Conn>,
    handles: Handles<B::Handle>,
}

impl<B: Backend> Local<B> {
    /// `resetBackend`: the handles go before their connection; the cancel
    /// handle leaves the shared state before the connection is freed.
    fn reset(&mut self, shared: &Shared<B>) {
        self.handles.clear();
        shared.lock().cancel = None;
        self.conn = None;
    }

    /// `ensureBackend`: the established connection, created on first use.
    fn ensure(&mut self, shared: &Shared<B>, spec: &LocationSpec, task: &TaskContext) -> Result<(), Status> {
        if self.conn.is_some() {
            return Ok(());
        }
        let backend = &shared.backend;
        let mut conn = backend.create(spec)?;
        {
            let mut state = shared.lock();
            let cancel = backend.cancel_handle(&conn);
            if state.stopping || task.canceled() {
                backend.cancel(&cancel);
            }
            state.cancel = Some(cancel);
        }
        let established = backend.establish(&mut conn, spec, task);
        self.conn = Some(conn);
        if established.is_err() {
            self.reset(shared);
        }
        established
    }
}

/// The worker thread (`Worker::run`).
fn run<B: Backend>(shared: &Shared<B>, spec: &LocationSpec, id: WorkerId) {
    let mut local: Local<B> = Local { conn: None, handles: Handles::new(Arc::clone(&shared.handles)) };
    loop {
        let (item, stopping) = {
            let mut state = shared.lock();
            while !state.stopping && state.queue.is_empty() {
                state = shared.wake.wait(state).unwrap_or_else(PoisonError::into_inner);
            }
            let stopping = state.stopping;
            let Some(item) = state.queue.pop_front() else { break };
            state.running = true;
            state.current = Some(Arc::clone(&item.task.cancel));
            drop(state);
            (item, stopping)
        };
        let ready = if stopping || item.task.canceled() {
            Err(canceled())
        } else {
            local.ensure(shared, spec, &item.task)
        };
        let established = ready.is_ok();
        let conn = match (ready, local.conn.as_mut()) {
            (Ok(()), Some(conn)) => Ok(conn),
            (Ok(()), None) => Err(Status::internal("no connection after establish")),
            (Err(status), _) => Err(status),
        };
        let result = (item.work)(Turn { ready: conn, handles: Some(&mut local.handles), worker: Some(id) });
        if established && (drops_connection(&result) || item.task.canceled()) {
            local.reset(shared);
        } else if established && let Some(conn) = local.conn.as_mut() {
            shared.backend.reset_cancel(conn);
        }
        let mut state = shared.lock();
        state.running = false;
        state.current = None;
        state.last_activity = Instant::now();
    }
    local.reset(shared);
    shared.finished.store(true, Ordering::Release);
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
