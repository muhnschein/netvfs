// SPDX-License-Identifier: LGPL-2.1-or-later
//! The locations a consumer may see and their connection pools: netvfs accounts whose Files service is enabled.
//!
//! Lives in the core (one task, no locks). The core owns reading the accounts database and the consent state: it hands the book the accounts the consumer may use at their levels ([`LocationBook::set_accounts`]) and says whether the user has decided.

use super::TaskContext;
use super::pool::{Pool, PoolSet};
use super::spec::LocationSpec;
use super::state::ConnectionState;
use super::worker::{Backend, Turn, Work, WorkerId};
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::Lane;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Locations and pools.
pub struct LocationBook<B: Backend> {
    accounts: Vec<Arc<LocationSpec>>,
    pools: PoolSet<B>,
}

impl<B: Backend> fmt::Debug for LocationBook<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocationBook")
            .field("accounts", &self.accounts.len())
            .field("pools", &self.pools)
            .finish_non_exhaustive()
    }
}

/// `PermissionDenied` before the user decided what this app may do.
#[must_use]
pub fn no_consent() -> Status {
    Status::new(ErrorName::PermissionDenied, "The user has not decided yet what this app may do")
}

/// `PermissionDenied` for an account the user has not allowed (or not decided on) for this app.
#[must_use]
pub fn not_allowed() -> Status {
    Status::new(ErrorName::PermissionDenied, "The user has not allowed this app to use this account")
        .with_detail("denied")
}

/// `NotFound`.
#[must_use]
pub fn no_such_location() -> Status {
    Status::new(ErrorName::NotFound, "No such location")
}

/// `Unsupported`.
#[must_use]
pub fn no_backend(provider: &str) -> Status {
    Status::new(ErrorName::Unsupported, format!("No backend for {provider} is installed"))
}

impl<B: Backend> LocationBook<B> {
    /// An empty book over `pools`.
    #[must_use]
    pub const fn new(pools: PoolSet<B>) -> Self {
        Self { accounts: Vec::new(), pools }
    }

    /// The pools.
    #[must_use]
    pub const fn pools(&self) -> &PoolSet<B> {
        &self.pools
    }

    /// The pools, for copy jobs and the core's own submissions.
    pub const fn pools_mut(&mut self) -> &mut PoolSet<B> {
        &mut self.pools
    }

    /// Takes the account list.
    pub fn set_accounts(&mut self, accounts: Vec<LocationSpec>) {
        let accounts: Vec<Arc<LocationSpec>> = accounts.into_iter().map(Arc::new).collect();
        self.pools.retain(|pool| accounts.iter().any(|a| a.id == pool.id && a.same_connection(&pool.params)));
        self.accounts = accounts;
    }

    /// The user's decision was removed.
    pub fn revoke(&mut self) {
        self.pools.clear();
    }

    /// Wakes every running item to look at its cancel flag.
    pub fn kick(&mut self) {
        self.pools.kick();
    }

    /// Closes connections idle for `idle` (and frees finished ones).
    pub fn maintain(&mut self, now: Instant, idle: Duration) -> bool {
        self.pools.maintain(now, idle)
    }

    /// What `ListLocations` shows.
    pub fn visible(&self) -> impl Iterator<Item = &Arc<LocationSpec>> {
        self.accounts.iter()
    }

    /// The location `id`, if the consumer can see it.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&Arc<LocationSpec>> {
        self.accounts.iter().find(|a| a.id == id)
    }

    /// The connection state of the visible location `id`.
    #[must_use]
    pub fn state(&self, id: &str) -> ConnectionState {
        self.pools.get(id).map_or(ConnectionState::Disconnected, Pool::state)
    }

    /// The connection states of what `ListLocations` shows, by id.
    #[must_use]
    pub fn states(&self) -> BTreeMap<String, ConnectionState> {
        self.visible().map(|spec| (spec.id.clone(), self.state(&spec.id))).collect()
    }

    /// Whether the visible location `id` has a pool.
    #[must_use]
    pub fn has_pool(&self, id: &str) -> bool {
        self.pools.get(id).is_some()
    }

    /// Makes sure the location `id` has a pool (`pool`), for a call that
    /// needs a connection.
    ///
    /// # Errors
    /// `PermissionDenied` before the user decided, `NotFound` for an unknown id,
    /// `Unsupported` when the provider's backend is missing.
    pub fn ensure_pool(
        &mut self,
        id: &str,
        decided: bool,
        provider_available: impl FnOnce(&str) -> bool,
    ) -> Result<&Arc<LocationSpec>, Status> {
        if !decided {
            return Err(no_consent());
        }
        let spec = Arc::clone(self.find(id).ok_or_else(no_such_location)?);
        if self.pools.get(id).is_none() {
            if !provider_available(&spec.provider) {
                return Err(no_backend(&spec.provider));
            }
            self.pools.add(Arc::clone(&spec));
        }
        self.find(id).ok_or_else(no_such_location)
    }

    /// `Disconnect`.
    pub fn disconnect(&mut self, id: &str) {
        if self.has_pool(id) {
            self.pools.stop_all(id);
        }
    }

    /// Closes read handle `handle` on the connection `worker` of `loc`.
    pub fn close_worker_handle(&mut self, loc: &str, worker: WorkerId, handle: u32) {
        if !self.has_pool(loc) || !self.pools.owns(loc, worker) {
            return;
        }
        let work: Work<B> = Box::new(move |turn: Turn<'_, B>| {
            if let Some(handles) = turn.handles {
                drop(handles.remove(handle));
            }
            Ok(())
        });
        self.pools.submit_to(loc, worker, TaskContext::detached(), work);
    }

    /// [`PoolSet::submit`] on the location `id`'s pool.
    pub fn submit(&mut self, id: &str, lane: Lane, task: TaskContext, work: Work<B>) {
        self.pools.submit(id, lane, task, work);
    }

    /// [`PoolSet::submit_to`].
    pub fn submit_to(&mut self, id: &str, worker: WorkerId, task: TaskContext, work: Work<B>) {
        self.pools.submit_to(id, worker, task, work);
    }
}

#[cfg(test)]
#[path = "book_tests.rs"]
mod tests;
