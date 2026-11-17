// SPDX-License-Identifier: LGPL-2.1-or-later
//! Tests only: a [`Backend`] without C++, recording what workers do with their connections.
#![allow(clippy::arithmetic_side_effects, clippy::missing_panics_doc, missing_docs)]

use super::TaskContext;
use super::spec::{Attention, LocationSpec};
use super::worker::{Backend, Turn, Work};
use crate::Status;
use crate::ffi::Params;
use netvfs_bridge_proto::ErrorName;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct MockConn {
    pub id: u64,
    canceled: Arc<AtomicBool>,
    mock: Arc<Inner>,
}

impl MockConn {
    pub fn canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }
}

impl Drop for MockConn {
    fn drop(&mut self) {
        self.mock.log(format!("free {}", self.id));
        self.mock.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct MockHandle {
    pub name: String,
    mock: Arc<Inner>,
}

impl MockHandle {
    pub fn new(mock: &Mock, name: &str) -> Self {
        Self { name: name.to_owned(), mock: Arc::clone(&mock.0) }
    }
}

impl Drop for MockHandle {
    fn drop(&mut self) {
        self.mock.log(format!("close {}", self.name));
    }
}

#[derive(Debug, Default)]
pub struct Inner {
    log: Mutex<Vec<String>>,
    next: AtomicU64,
    live: AtomicUsize,
    create: Mutex<VecDeque<Result<(), Status>>>,
    establish: Mutex<VecDeque<Result<(), Status>>>,
    hold: AtomicBool,
    hold_create: AtomicBool,
}

impl Inner {
    fn log(&self, line: String) {
        self.log.lock().unwrap().push(line);
    }
}

#[derive(Debug, Default, Clone)]
pub struct Mock(pub Arc<Inner>);

impl Mock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn log(&self) -> Vec<String> {
        self.0.log.lock().unwrap().clone()
    }

    pub fn count(&self, prefix: &str) -> usize {
        self.log().iter().filter(|l| l.starts_with(prefix)).count()
    }

    pub fn live(&self) -> usize {
        self.0.live.load(Ordering::Acquire)
    }

    pub fn fail_create(&self, status: Status) {
        self.0.create.lock().unwrap().push_back(Err(status));
    }

    pub fn fail_establish(&self, status: Status) {
        self.queue_establish(Err(status));
    }

    pub fn queue_establish(&self, result: Result<(), Status>) {
        self.0.establish.lock().unwrap().push_back(result);
    }

    pub fn hold_create(&self, on: bool) {
        self.0.hold_create.store(on, Ordering::Release);
    }

    pub fn hold_establish(&self, on: bool) {
        self.0.hold.store(on, Ordering::Release);
    }

    pub fn wait_for(&self, prefix: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.count(prefix) < n {
            assert!(Instant::now() < deadline, "no {n} x {prefix} in {:?}", self.log());
            thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Backend for Mock {
    type Conn = MockConn;
    type Handle = MockHandle;
    type Cancel = (u64, Arc<AtomicBool>, Arc<Inner>);

    fn create(&self, spec: &LocationSpec) -> Result<MockConn, Status> {
        if self.0.hold_create.load(Ordering::Acquire) {
            self.0.log("creating".to_owned());
            while self.0.hold_create.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(2));
            }
        }
        let next = self.0.create.lock().unwrap_or_else(PoisonError::into_inner).pop_front();
        next.unwrap_or(Ok(()))?;
        let id = self.0.next.fetch_add(1, Ordering::AcqRel) + 1;
        self.0.live.fetch_add(1, Ordering::AcqRel);
        self.0.log(format!("create {id} {}", spec.id));
        Ok(MockConn { id, canceled: Arc::default(), mock: Arc::clone(&self.0) })
    }

    fn cancel_handle(&self, conn: &MockConn) -> Self::Cancel {
        (conn.id, Arc::clone(&conn.canceled), Arc::clone(&self.0))
    }

    fn cancel(&self, handle: &Self::Cancel) {
        handle.1.store(true, Ordering::Release);
        handle.2.log(format!("cancel {}", handle.0));
    }

    fn establish(&self, conn: &mut MockConn, _spec: &LocationSpec, task: &TaskContext) -> Result<(), Status> {
        self.0.log(format!("establish {} s{}", conn.id, task.session.0));
        while self.0.hold.load(Ordering::Acquire) {
            if conn.canceled() {
                return Err(Status::new(ErrorName::Canceled, "held"));
            }
            thread::sleep(Duration::from_millis(2));
        }
        let next = self.0.establish.lock().unwrap_or_else(PoisonError::into_inner).pop_front();
        next.unwrap_or(Ok(()))
    }

    fn reset_cancel(&self, conn: &mut MockConn) {
        conn.canceled.store(false, Ordering::Release);
        self.0.log(format!("reset {}", conn.id));
    }
}

pub fn spec(id: &str, host: &str) -> Arc<LocationSpec> {
    let params = Params { provider: "fake".into(), host: host.into(), ..Params::default() };
    let mut spec = LocationSpec::account(1, "fake", id, params, Vec::new(), Attention::None);
    spec.id = id.to_owned();
    Arc::new(spec)
}

pub fn task() -> TaskContext {
    TaskContext::detached()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Conn(u64),
    Failed(ErrorName),
    Pending(ErrorName),
}

fn seen(turn: &Turn<'_, Mock>) -> Seen {
    match (&turn.ready, turn.worker) {
        (Ok(conn), _) => Seen::Conn(conn.id),
        (Err(s), Some(_)) => Seen::Failed(s.name),
        (Err(s), None) => Seen::Pending(s.name),
    }
}

pub fn reporting(tx: &mpsc::Sender<Seen>, result: Result<(), Status>) -> Work<Mock> {
    let tx = tx.clone();
    Box::new(move |turn: Turn<'_, Mock>| {
        drop(tx.send(seen(&turn)));
        result
    })
}

pub fn blocking(tx: &mpsc::Sender<Seen>, go: mpsc::Receiver<()>, result: Result<(), Status>) -> Work<Mock> {
    let tx = tx.clone();
    Box::new(move |turn: Turn<'_, Mock>| {
        drop(tx.send(seen(&turn)));
        let canceled = turn.ready.as_ref().map(|c| Arc::clone(&c.canceled)).ok();
        loop {
            if go.recv_timeout(Duration::from_millis(2)).is_ok() {
                return result;
            }
            if canceled.as_ref().is_some_and(|c| c.load(Ordering::Acquire)) {
                return Err(Status::new(ErrorName::Canceled, "conn canceled"));
            }
        }
    })
}

pub fn recv(rx: &mpsc::Receiver<Seen>) -> Seen {
    rx.recv_timeout(Duration::from_secs(10)).expect("a work item ran")
}

pub fn status(name: ErrorName) -> Status {
    Status::new(name, "")
}
