// SPDX-License-Identifier: LGPL-2.1-or-later
//! Connection pools per location: lanes as the consumer hints them (interactive 1, bulk 2, stream 1 connection) and at most 4 connections per host across all locations of the consumer. Core actor only: no locks.
//!
//! [`PoolSet`] holds all pools with the host counts together: picking a connection may close an idle one of another pool on the same host, and a freed slot lets waiting work of every pool on that host retry.
//!
//! A stopped connection keeps its host slot until its thread has finished (the worker's `finished` flag), except one closed to make room, whose slot counts as free at once.
//! Nothing waits for a thread: stopped workers are dropped once finished (reaped on [`PoolSet::submit`] and [`PoolSet::maintain`]).
//!
//! [`Pool::state`] is the location's [`ConnectionState`] from its live connections and its [`StateTracker`]; every change raises the set's [`StateSignal`]: a worker's phase or attempt, and a connection stopped here.

use super::spec::LocationSpec;
use super::state::{ConnectionState, Phase, StateSignal, StateTracker};
use super::worker::{Backend, Turn, Work, Worker, WorkerId};
use super::{TaskContext, canceled};
use crate::Status;
use netvfs_bridge_proto::limits::{POOL_PER_HOST, pool_size};
use netvfs_bridge_proto::{ErrorName, Lane};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Connections closed after this long without work.
pub const CONNECTION_IDLE: Duration = Duration::from_mins(1);

/// Connection counts per host.
#[derive(Debug, Clone)]
pub struct HostRegistry {
    per_host: usize,
    used: HashMap<String, usize>,
}

impl Default for HostRegistry {
    fn default() -> Self {
        Self::new(POOL_PER_HOST)
    }
}

impl HostRegistry {
    /// A registry with `per_host` connections per host.
    #[must_use]
    pub fn new(per_host: usize) -> Self {
        Self { per_host, used: HashMap::new() }
    }

    /// Takes `count` slots of `host`.
    pub fn try_acquire(&mut self, host: &str, count: usize) -> bool {
        let used = self.used.entry(host.to_owned()).or_insert(0);
        match used.checked_add(count) {
            Some(n) if n <= self.per_host => {
                *used = n;
                true
            }
            _ => {
                if *used == 0 {
                    self.used.remove(host);
                }
                false
            }
        }
    }

    /// Gives `count` slots of `host` back.
    pub fn release(&mut self, host: &str, count: usize) {
        let Some(used) = self.used.get_mut(host) else { return };
        *used = used.saturating_sub(count);
        if *used == 0 {
            self.used.remove(host);
        }
    }

    /// Slots of `host` in use.
    #[must_use]
    pub fn in_use(&self, host: &str) -> usize {
        self.used.get(host).copied().unwrap_or(0)
    }

    /// The limit per host.
    #[must_use]
    pub const fn per_host(&self) -> usize {
        self.per_host
    }

    /// Hosts with slots in use.
    #[must_use]
    pub fn hosts_in_use(&self) -> usize {
        self.used.len()
    }
}

struct Retired<B: Backend> {
    worker: Worker<B>,
    host: String,
    counted: bool,
}

struct Pending<B: Backend> {
    lane: Lane,
    task: TaskContext,
    work: Work<B>,
}

/// The connections of one location.
pub struct Pool<B: Backend> {
    spec: Arc<LocationSpec>,
    host: String,
    workers: Vec<Worker<B>>,
    retired: Vec<Retired<B>>,
    pending: Vec<Pending<B>>,
    tracker: Arc<StateTracker>,
}

impl<B: Backend> fmt::Debug for Pool<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("location", &self.spec.id)
            .field("connections", &self.workers.len())
            .field("retired", &self.retired.len())
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl<B: Backend> Pool<B> {
    fn new(spec: Arc<LocationSpec>, signal: StateSignal) -> Self {
        let host = spec.host_key();
        let tracker = StateTracker::new(signal);
        Self { spec, host, workers: Vec::new(), retired: Vec::new(), pending: Vec::new(), tracker }
    }

    /// The location.
    #[must_use]
    pub const fn spec(&self) -> &Arc<LocationSpec> {
        &self.spec
    }

    /// Whether `worker` is one of its live connections (read handles are checked through this before each use).
    #[must_use]
    pub fn owns(&self, worker: WorkerId) -> bool {
        self.workers.iter().any(|w| w.id() == worker)
    }

    /// Live connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.workers.len()
    }

    /// Work waiting for a connection.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing waits and every connection is idle.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty() && self.workers.iter().all(|w| w.idle_since().is_some())
    }

    /// The location's connection state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        let mut connecting = false;
        for w in &self.workers {
            match w.phase() {
                Phase::Established => return ConnectionState::Connected,
                Phase::Connecting => connecting = true,
                Phase::Closed => {}
            }
        }
        if connecting {
            return ConnectionState::Connecting;
        }
        self.tracker.failure().map_or(ConnectionState::Disconnected, ConnectionState::Failed)
    }

    fn least_loaded(&self, lane: Lane, any_lane: bool) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (i, w) in self.workers.iter().enumerate() {
            if !any_lane && w.lane() != lane {
                continue;
            }
            let load = w.load();
            if best.is_none_or(|(_, b)| load < b) {
                best = Some((i, load));
            }
        }
        best.map(|(i, _)| i)
    }

    fn kick(&mut self) {
        for w in &self.workers {
            w.kick();
        }
        let (gone, keep) = std::mem::take(&mut self.pending).into_iter().partition(|p| p.task.canceled());
        self.pending = keep;
        for p in gone {
            end_pending(p);
        }
    }

    fn retire(&mut self, index: usize, counted: bool) {
        if index < self.workers.len() {
            let worker = self.workers.remove(index);
            worker.stop();
            self.retired.push(Retired { worker, host: self.host.clone(), counted });
            self.tracker.changed();
        }
    }

    fn stop_all(&mut self) {
        while !self.workers.is_empty() {
            self.retire(0, true);
        }
        self.tracker.clear();
    }

    fn close_one_idle(&mut self) -> bool {
        let Some(index) = self.workers.iter().position(|w| w.idle_since().is_some() && w.open_handles() == 0)
        else {
            return false;
        };
        self.retire(index, false);
        true
    }

    fn reap(&mut self) -> usize {
        reap(&mut self.retired)
    }
}

impl<B: Backend> Drop for Pool<B> {
    fn drop(&mut self) {
        // All threads stop at once; dropping each then waits for it.
        for w in &self.workers {
            w.stop();
        }
        for p in std::mem::take(&mut self.pending) {
            end_pending(p);
        }
    }
}

fn end_pending<B: Backend>(p: Pending<B>) {
    drop((p.work)(Turn::failed(canceled())));
}

fn reap<B: Backend>(retired: &mut Vec<Retired<B>>) -> usize {
    let mut released = 0_usize;
    retired.retain(|r| {
        let done = r.worker.finished();
        if done && r.counted {
            released = released.saturating_add(1);
        }
        !done
    });
    released
}

/// The pools of all locations of a consumer, with their host counts.
pub struct PoolSet<B: Backend> {
    backend: Arc<B>,
    hosts: HostRegistry,
    pools: Vec<Pool<B>>,
    orphans: Vec<Retired<B>>,
    signal: StateSignal,
}

impl<B: Backend> fmt::Debug for PoolSet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolSet")
            .field("hosts", &self.hosts)
            .field("pools", &self.pools)
            .field("orphans", &self.orphans.len())
            .finish_non_exhaustive()
    }
}

impl<B: Backend> PoolSet<B> {
    /// No pools.
    #[must_use]
    pub fn new(backend: Arc<B>, per_host: usize) -> Self {
        Self {
            backend,
            hosts: HostRegistry::new(per_host),
            pools: Vec::new(),
            orphans: Vec::new(),
            signal: StateSignal::default(),
        }
    }

    /// The same, with changes of the pools' states raising `signal`.
    #[must_use]
    pub fn with_signal(mut self, signal: StateSignal) -> Self {
        self.signal = signal;
        self
    }

    /// The backend the connections use.
    #[must_use]
    pub const fn backend(&self) -> &Arc<B> {
        &self.backend
    }

    /// The host counts.
    #[must_use]
    pub const fn hosts(&self) -> &HostRegistry {
        &self.hosts
    }

    fn index(&self, id: &str) -> Option<usize> {
        self.pools.iter().position(|p| p.spec.id == id)
    }

    /// The pool of location `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pool<B>> {
        self.pools.iter().find(|p| p.spec.id == id)
    }

    /// The pools, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Pool<B>> {
        self.pools.iter()
    }

    /// Adds a pool for `spec` unless its location has one.
    pub fn add(&mut self, spec: Arc<LocationSpec>) -> bool {
        if self.index(&spec.id).is_some() {
            return false;
        }
        self.pools.push(Pool::new(spec, self.signal.clone()));
        true
    }

    /// Queues `work` on a connection of `lane` of location `id`.
    pub fn submit(&mut self, id: &str, lane: Lane, task: TaskContext, work: Work<B>) {
        match self.index(id) {
            Some(index) => self.submit_at(index, lane, task, work),
            None => drop(work(Turn::failed(Status::new(ErrorName::NotFound, "No such location")))),
        }
    }

    /// Queues `work` on the connection `worker` of location `id` (where its read handles live).
    pub fn submit_to(&mut self, id: &str, worker: WorkerId, task: TaskContext, work: Work<B>) {
        match self.get(id).and_then(|p| p.workers.iter().find(|w| w.id() == worker)) {
            Some(w) => w.post(task, work),
            None => drop(work(Turn::failed(Status::new(
                ErrorName::ConnectionLost,
                "The connection of this handle was closed",
            )))),
        }
    }

    /// Whether `worker` is a live connection of location `id`.
    #[must_use]
    pub fn owns(&self, id: &str, worker: WorkerId) -> bool {
        self.get(id).is_some_and(|p| p.owns(worker))
    }

    fn submit_at(&mut self, index: usize, lane: Lane, task: TaskContext, work: Work<B>) {
        // Connections closed by Disconnect free their host slots first.
        self.reap_pool(index);
        self.reap_orphans();
        match self.pick(index, lane) {
            Ok(Some(w)) => {
                if let Some(worker) = self.pools.get(index).and_then(|p| p.workers.get(w)) {
                    worker.post(task, work);
                }
            }
            Ok(None) => {
                if let Some(pool) = self.pools.get_mut(index) {
                    pool.pending.push(Pending { lane, task, work });
                }
            }
            Err(status) => drop(work(Turn::failed(status))),
        }
    }

    fn pick(&mut self, index: usize, lane: Lane) -> Result<Option<usize>, Status> {
        let Some(pool) = self.pools.get(index) else { return Ok(None) };
        let existing = pool.least_loaded(lane, false);
        if let Some(e) = existing
            && pool.workers.get(e).is_some_and(|w| w.load() == 0)
        {
            return Ok(Some(e));
        }
        let in_lane = pool.workers.iter().filter(|w| w.lane() == lane).count();
        let host = pool.host.clone();
        if in_lane < pool_size(lane)
            && (self.hosts.try_acquire(&host, 1)
                || (self.evict_idle(&host, index) && self.hosts.try_acquire(&host, 1)))
        {
            let Some(pool) = self.pools.get_mut(index) else { return Ok(None) };
            let tracker = Arc::clone(&pool.tracker);
            match Worker::start(Arc::clone(&self.backend), Arc::clone(&pool.spec), lane, tracker) {
                Ok(worker) => {
                    pool.workers.push(worker);
                    return Ok(Some(pool.workers.len().saturating_sub(1)));
                }
                Err(e) => {
                    self.hosts.release(&host, 1);
                    return Err(Status::internal(format!("Cannot start a connection thread: {e}")));
                }
            }
        }
        if existing.is_some() {
            return Ok(existing);
        }
        // No connection of this lane and the host is full: borrow another
        // lane's.
        Ok(self.pools.get(index).and_then(|p| p.least_loaded(lane, true)))
    }

    fn evict_idle(&mut self, host: &str, except: usize) -> bool {
        for (i, pool) in self.pools.iter_mut().enumerate() {
            if i != except && pool.host == host && pool.close_one_idle() {
                // Counted free now: the connection is already being closed.
                self.hosts.release(host, 1);
                return true;
            }
        }
        false
    }

    fn notify_released(&mut self, host: &str) {
        for index in 0..self.pools.len() {
            let Some(pool) = self.pools.get_mut(index) else { continue };
            if pool.host != host {
                continue;
            }
            for p in std::mem::take(&mut pool.pending) {
                self.submit_at(index, p.lane, p.task, p.work);
            }
        }
    }

    fn reap_pool(&mut self, index: usize) -> bool {
        let Some(pool) = self.pools.get_mut(index) else { return false };
        let before = pool.retired.len();
        let released = pool.reap();
        let host = pool.host.clone();
        let changed = before != pool.retired.len();
        if released > 0 {
            self.hosts.release(&host, released);
            self.notify_released(&host);
        }
        changed
    }

    fn reap_orphans(&mut self) -> bool {
        let mut hosts: Vec<String> = Vec::new();
        let before = self.orphans.len();
        self.orphans.retain(|r| {
            let done = r.worker.finished();
            if done && r.counted {
                hosts.push(r.host.clone());
            }
            !done
        });
        for host in &hosts {
            self.hosts.release(host, 1);
        }
        for host in &hosts {
            self.notify_released(host);
        }
        before != self.orphans.len()
    }

    /// Cancels the work whose flags were set.
    pub fn kick(&mut self) {
        for pool in &mut self.pools {
            pool.kick();
        }
    }

    /// Stops the connections idle for `idle` or longer without open handles, and drops finished ones.
    pub fn maintain(&mut self, now: Instant, idle: Duration) -> bool {
        let mut changed = false;
        for index in 0..self.pools.len() {
            if let Some(pool) = self.pools.get_mut(index) {
                let mut i = 0;
                while let Some(w) = pool.workers.get(i) {
                    let expired =
                        w.idle_since().is_some_and(|since| now.saturating_duration_since(since) >= idle);
                    if expired && w.open_handles() == 0 {
                        pool.retire(i, true);
                        changed = true;
                    } else {
                        i = i.saturating_add(1);
                    }
                }
            }
            changed |= self.reap_pool(index);
        }
        changed |= self.reap_orphans();
        changed
    }

    /// Stops every connection of location `id` (`Disconnect`).
    pub fn stop_all(&mut self, id: &str) {
        if let Some(index) = self.index(id)
            && let Some(pool) = self.pools.get_mut(index)
        {
            pool.stop_all();
        }
    }

    /// Removes the pool of location `id`.
    pub fn remove(&mut self, id: &str) -> bool {
        let Some(index) = self.index(id) else { return false };
        let mut pool = self.pools.remove(index);
        pool.stop_all();
        self.orphans.append(&mut pool.retired);
        // Dropping the pool ends its pending work.
        true
    }

    /// Removes the pools whose location `keep` refuses.
    pub fn retain(&mut self, mut keep: impl FnMut(&LocationSpec) -> bool) {
        let gone: Vec<String> =
            self.pools.iter().filter(|p| !keep(&p.spec)).map(|p| p.spec.id.clone()).collect();
        for id in gone {
            self.remove(&id);
        }
    }

    /// Removes every pool (revocation).
    pub fn clear(&mut self) {
        self.retain(|_| false);
    }

    /// Whether no pool has work.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.pools.iter().all(Pool::is_idle)
    }

    /// Takes a slot on `host` for work outside the pools (a copy job).
    pub fn try_acquire_host(&mut self, host: &str) -> bool {
        self.hosts.try_acquire(host, 1)
    }

    /// Gives back a slot taken with [`PoolSet::try_acquire_host`].
    pub fn release_host(&mut self, host: &str) {
        self.hosts.release(host, 1);
        self.notify_released(host);
    }

    /// Stopped connections whose threads have not finished yet.
    #[must_use]
    pub fn closing(&self) -> usize {
        self.orphans.len().saturating_add(self.pools.iter().map(|p| p.retired.len()).sum())
    }
}

#[cfg(test)]
#[path = "pool_tests.rs"]
mod tests;
