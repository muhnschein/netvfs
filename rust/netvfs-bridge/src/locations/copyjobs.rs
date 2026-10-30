// SPDX-License-Identifier: LGPL-2.1-or-later
//! `CopyAcross`: two connections on a thread of their own. `Ops::copyAcross` needs both backends owned by the calling thread, so a copy job does not use the pools; it takes one host slot per side and is refused with `TooManyConnections` when a host is full.
//!
//! The thread creates and establishes both connections, runs the body and frees them, then reports [`WorkerEvent::CopyDone`]; the core answers with [`CopyJobs::finish`], which waits for the thread (it has ended) and gives the host slots back.

use super::pool::PoolSet;
use super::spec::LocationSpec;
use super::worker::Backend;
use super::{TaskContext, WorkerEvent, WorkerEvents};
use crate::Status;
use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::limits::RETRY_AFTER_MS;
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

/// The name of copy job threads.
pub const THREAD_NAME: &str = "nvb-copy";

/// A copy job, unique within its [`CopyJobs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CopyId(pub u64);

/// What a copy job does with its two established connections (source, destination), on its thread.
pub type CopyBody<B> = Box<
    dyn for<'a> FnOnce(&'a mut <B as Backend>::Conn, &'a mut <B as Backend>::Conn) -> Result<(), Status>
        + Send,
>;

type Cancels<B> = Arc<Mutex<Vec<<B as Backend>::Cancel>>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Job<B: Backend> {
    id: CopyId,
    task: TaskContext,
    cancels: Cancels<B>,
    thread: Option<JoinHandle<()>>,
    hosts: [String; 2],
}

/// The running copy jobs of a consumer (core actor only).
pub struct CopyJobs<B: Backend> {
    backend: Arc<B>,
    events: WorkerEvents,
    jobs: Vec<Job<B>>,
    next: u64,
}

impl<B: Backend> fmt::Debug for CopyJobs<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<CopyId> = self.jobs.iter().map(|j| j.id).collect();
        f.debug_struct("CopyJobs").field("jobs", &ids).finish_non_exhaustive()
    }
}

/// `TooManyConnections` with the retry time.
#[must_use]
pub fn too_many_connections() -> Status {
    Status::new(ErrorName::TooManyConnections, "Too many connections to the server")
        .with_retry_after_ms(i64::try_from(RETRY_AFTER_MS).unwrap_or(i64::MAX))
}

impl<B: Backend> CopyJobs<B> {
    /// No jobs.
    #[must_use]
    pub const fn new(backend: Arc<B>, events: WorkerEvents) -> Self {
        Self { backend, events, jobs: Vec::new(), next: 1 }
    }

    /// Starts copying with `body` from `source` to `destination` for
    /// `task`, taking a host slot for each from `pools`.
    ///
    /// # Errors
    /// `TooManyConnections` (with `retryAfterMs`) when a host is full;
    /// `Internal` when the thread cannot start. Nothing is held then.
    pub fn start(
        &mut self,
        pools: &mut PoolSet<B>,
        source: Arc<LocationSpec>,
        destination: Arc<LocationSpec>,
        task: TaskContext,
        body: CopyBody<B>,
    ) -> Result<CopyId, Status> {
        let hosts = [source.host_key(), destination.host_key()];
        let [source_host, destination_host] = &hosts;
        if !pools.try_acquire_host(source_host) {
            return Err(too_many_connections());
        }
        if !pools.try_acquire_host(destination_host) {
            pools.release_host(source_host);
            return Err(too_many_connections());
        }
        let id = CopyId(self.next);
        self.next = self.next.wrapping_add(1);
        let cancels: Cancels<B> = Arc::new(Mutex::new(Vec::new()));
        let run = {
            let (backend, events, cancels, task) =
                (Arc::clone(&self.backend), self.events.clone(), Arc::clone(&cancels), task.clone());
            move || {
                let result = run_copy(&*backend, &cancels, &source, &destination, &task, body);
                events.send(WorkerEvent::CopyDone { id, result });
            }
        };
        match std::thread::Builder::new().name(THREAD_NAME.to_owned()).spawn(run) {
            Ok(thread) => {
                self.jobs.push(Job { id, task, cancels, thread: Some(thread), hosts });
                Ok(id)
            }
            Err(e) => {
                pools.release_host(source_host);
                pools.release_host(destination_host);
                Err(Status::internal(format!("Cannot start a copy thread: {e}")))
            }
        }
    }

    /// The job `id` reported [`WorkerEvent::CopyDone`].
    pub fn finish(&mut self, id: CopyId, pools: &mut PoolSet<B>) -> bool {
        let Some(index) = self.jobs.iter().position(|j| j.id == id) else { return false };
        let mut job = self.jobs.remove(index);
        if let Some(thread) = job.thread.take() {
            // The thread has sent its last event; a panic aborted the
            // process already (panic = "abort").
            drop(thread.join());
        }
        let [source_host, destination_host] = &job.hosts;
        pools.release_host(source_host);
        pools.release_host(destination_host);
        true
    }

    /// Cancels the connections of the jobs whose flags are set.
    pub fn kick(&self) {
        for job in self.jobs.iter().filter(|j| j.task.canceled()) {
            for cancel in lock(&job.cancels).iter() {
                self.backend.cancel(cancel);
            }
        }
    }

    /// Whether no job runs.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Running jobs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// Whether no job runs (same as [`CopyJobs::is_idle`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

impl<B: Backend> Drop for CopyJobs<B> {
    fn drop(&mut self) {
        for job in &self.jobs {
            job.task.cancel.store(true, Ordering::Release);
            for cancel in lock(&job.cancels).iter() {
                self.backend.cancel(cancel);
            }
        }
        for job in &mut self.jobs {
            if let Some(thread) = job.thread.take() {
                drop(thread.join());
            }
        }
    }
}

fn run_copy<B: Backend>(
    backend: &B,
    cancels: &Mutex<Vec<B::Cancel>>,
    source: &LocationSpec,
    destination: &LocationSpec,
    task: &TaskContext,
    body: CopyBody<B>,
) -> Result<(), Status> {
    let (mut src, mut dst) = (backend.create(source)?, backend.create(destination)?);
    *lock(cancels) = vec![backend.cancel_handle(&src), backend.cancel_handle(&dst)];
    let result = backend
        .establish(&mut src, source, task)
        .and_then(|()| backend.establish(&mut dst, destination, task))
        .and_then(|()| body(&mut src, &mut dst));
    lock(cancels).clear();
    drop(src);
    drop(dst);
    result
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects, reason = "tests")]
mod tests {
    use super::*;
    use crate::locations::mock::{Mock, MockConn, spec, status, task};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    type Rx = tokio::sync::mpsc::UnboundedReceiver<WorkerEvent>;

    fn jobs(per_host: usize) -> (Arc<Mock>, PoolSet<Mock>, CopyJobs<Mock>, Rx) {
        let mock = Mock::new();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let jobs = CopyJobs::new(Arc::clone(&mock), WorkerEvents::channel(tx));
        (Arc::clone(&mock), PoolSet::new(mock, per_host), jobs, rx)
    }

    fn done(rx: &mut Rx) -> (CopyId, Result<(), Status>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match rx.try_recv() {
                Ok(WorkerEvent::CopyDone { id, result }) => return (id, result),
                Ok(other) => panic!("unexpected {other:?}"),
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("no CopyDone: {e}"),
            }
        }
    }

    fn body(tx: &mpsc::Sender<(u64, u64, Option<String>)>, result: Result<(), Status>) -> CopyBody<Mock> {
        let tx = tx.clone();
        Box::new(move |src: &mut MockConn, dst: &mut MockConn| {
            tx.send((src.id, dst.id, std::thread::current().name().map(str::to_owned))).unwrap();
            result
        })
    }

    #[test]
    fn copies_on_a_thread_and_gives_the_slots_back() {
        let (mock, mut pools, mut jobs, mut rx) = jobs(4);
        let (tx, seen) = mpsc::channel();
        assert_eq!((jobs.len(), jobs.is_idle(), jobs.is_empty()), (0, true, true));
        let id = jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), task(), body(&tx, Ok(()))).unwrap();
        assert_eq!(seen.recv().unwrap(), (1, 2, Some("nvb-copy".to_owned())));
        assert_eq!((jobs.len(), jobs.is_idle(), jobs.is_empty()), (1, false, false));
        assert_eq!((pools.hosts().in_use("fake://h:0"), pools.hosts().in_use("fake://i:0")), (1, 1));
        assert_eq!(done(&mut rx), (id, Ok(())));
        assert!(format!("{jobs:?}").contains("CopyId(1)"));
        assert!(jobs.finish(id, &mut pools));
        assert!(!jobs.finish(id, &mut pools));
        assert!(jobs.is_idle());
        assert_eq!(pools.hosts().hosts_in_use(), 0);
        assert_eq!(
            mock.log(),
            ["create 1 a", "create 2 b", "establish 1 s0", "establish 2 s0", "free 1", "free 2"]
        );
        let next = jobs.start(&mut pools, spec("a", "h"), spec("b", "h"), task(), body(&tx, Ok(()))).unwrap();
        assert_eq!(next, CopyId(2));
        assert_eq!(pools.hosts().in_use("fake://h:0"), 2);
        assert_eq!(done(&mut rx).0, next);
        jobs.finish(next, &mut pools);
        assert_eq!(pools.hosts().in_use("fake://h:0"), 0);
    }

    #[test]
    fn a_full_host_refuses() {
        let (_mock, mut pools, mut jobs, _rx) = jobs(1);
        let (tx, _seen) = mpsc::channel();
        assert!(pools.try_acquire_host("fake://h:0"));
        let refused =
            jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), task(), body(&tx, Ok(()))).unwrap_err();
        assert_eq!(refused, too_many_connections());
        assert_eq!(refused.retry_after_ms, 1000);
        assert_eq!(refused.message, "Too many connections to the server");
        assert_eq!(pools.hosts().in_use("fake://i:0"), 0);
        let refused =
            jobs.start(&mut pools, spec("a", "i"), spec("b", "h"), task(), body(&tx, Ok(()))).unwrap_err();
        assert_eq!(refused.name, ErrorName::TooManyConnections);
        assert_eq!(pools.hosts().in_use("fake://i:0"), 0);
        assert!(jobs.is_idle());
    }

    #[test]
    fn failures_on_the_way() {
        let (mock, mut pools, mut jobs, mut rx) = jobs(4);
        let (tx, seen) = mpsc::channel();
        mock.fail_establish(Status::new(ErrorName::NotFound, "x"));
        let id = jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), task(), body(&tx, Ok(()))).unwrap();
        assert_eq!(done(&mut rx).1.unwrap_err().name, ErrorName::NotFound);
        jobs.finish(id, &mut pools);
        assert_eq!(mock.count("establish"), 1);
        mock.queue_establish(Ok(()));
        mock.queue_establish(Err(status(ErrorName::AuthFailed)));
        let id = jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), task(), body(&tx, Ok(()))).unwrap();
        assert_eq!(done(&mut rx).1.unwrap_err().name, ErrorName::AuthFailed);
        jobs.finish(id, &mut pools);
        assert_eq!(mock.count("establish"), 3);
        assert!(seen.try_recv().is_err());
        mock.fail_create(status(ErrorName::Unsupported));
        let id = jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), task(), body(&tx, Ok(()))).unwrap();
        assert_eq!(done(&mut rx).1.unwrap_err().name, ErrorName::Unsupported);
        jobs.finish(id, &mut pools);
        assert!(seen.try_recv().is_err());
        assert_eq!(pools.hosts().hosts_in_use(), 0);
        assert_eq!(mock.live(), 0);
        let (mock, mut pools, mut jobs, mut rx) = self::jobs(4);
        let id = jobs
            .start(
                &mut pools,
                spec("a", "h"),
                spec("b", "i"),
                task(),
                body(&tx, Err(status(ErrorName::NoSpace))),
            )
            .unwrap();
        assert_eq!(done(&mut rx), (id, Err(status(ErrorName::NoSpace))));
        jobs.finish(id, &mut pools);
        assert_eq!(mock.live(), 0);
    }

    #[test]
    fn kick_and_drop_cancel_the_connections() {
        let (mock, mut pools, mut jobs, mut rx) = jobs(4);
        let t = task();
        let (go, wait) = mpsc::channel::<()>();
        let (tx, started) = mpsc::channel();
        let held: CopyBody<Mock> = Box::new(move |src: &mut MockConn, dst: &mut MockConn| {
            tx.send(()).unwrap();
            while !(src.canceled() && dst.canceled()) {
                if wait.recv_timeout(Duration::from_millis(2)).is_ok() {
                    return Ok(());
                }
            }
            Err(status(ErrorName::Canceled))
        });
        let id = jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), t.clone(), held).unwrap();
        started.recv().unwrap();
        jobs.kick();
        assert_eq!(mock.count("cancel"), 0);
        t.cancel.store(true, Ordering::Release);
        jobs.kick();
        assert_eq!(done(&mut rx), (id, Err(status(ErrorName::Canceled))));
        assert_eq!((mock.count("cancel 1"), mock.count("cancel 2")), (1, 1));
        jobs.finish(id, &mut pools);
        drop(go);
        let (go, wait) = mpsc::channel::<()>();
        let (tx, started) = mpsc::channel();
        let held: CopyBody<Mock> = Box::new(move |src: &mut MockConn, _dst: &mut MockConn| {
            tx.send(()).unwrap();
            while !src.canceled() {
                if wait.recv_timeout(Duration::from_millis(2)).is_ok() {
                    return Ok(());
                }
            }
            Err(status(ErrorName::Canceled))
        });
        let t = task();
        jobs.start(&mut pools, spec("a", "h"), spec("b", "i"), t.clone(), held).unwrap();
        started.recv().unwrap();
        drop(jobs);
        assert!(t.canceled());
        assert_eq!(mock.count("cancel 3"), 1);
        assert_eq!(mock.live(), 0);
        drop(go);
    }
}
