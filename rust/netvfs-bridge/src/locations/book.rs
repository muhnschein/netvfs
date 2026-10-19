// SPDX-License-Identifier: LGPL-2.1-or-later
//! The locations a consumer may see (XB-7) and their connection pools
//! (`LocationBook` of locationbook.cpp): netvfs accounts whose Files
//! service is enabled, and the ad-hoc locations consumers created.
//!
//! The book lives in the core (one task, no locks). Reading the accounts
//! database, the consent state and the known_hosts file are the core's
//! (chunk E): it hands the book the account list
//! ([`LocationBook::set_accounts`]), says whether consent is granted, and
//! passes its [`PinStore`] where a pin is dropped.

use super::TaskContext;
use super::connector::PinStore;
use super::pool::PoolSet;
use super::spec::{LocationKind, LocationSpec, ad_hoc_location_id};
use super::worker::{Backend, Turn, Work, WorkerId};
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::Lane;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{BuildHasher as _, RandomState};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Locations, ad-hoc secrets and pools.
pub struct LocationBook<B: Backend> {
    accounts: Vec<Arc<LocationSpec>>,
    ad_hoc: BTreeMap<String, Arc<LocationSpec>>,
    /// Ad-hoc locations whose first connection is being established; their
    /// pools exist (and count against the host limit) but nobody sees them.
    connecting: BTreeMap<String, Arc<LocationSpec>>,
    /// This run's part of the ad-hoc ids ([`new_run`]).
    run: u64,
    next_ad_hoc: u64,
    pools: PoolSet<B>,
}

impl<B: Backend> fmt::Debug for LocationBook<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocationBook")
            .field("accounts", &self.accounts.len())
            .field("ad_hoc", &self.ad_hoc.len())
            .field("connecting", &self.connecting.len())
            .field("pools", &self.pools)
            .finish_non_exhaustive()
    }
}

/// `PermissionDenied`: no consent (XB-6).
#[must_use]
pub fn no_consent() -> Status {
    Status::new(ErrorName::PermissionDenied, "The user has not allowed this app to use network locations")
}

/// `NotFound`: an id the consumer cannot see.
#[must_use]
pub fn no_such_location() -> Status {
    Status::new(ErrorName::NotFound, "No such location")
}

/// A random number for this run of the bridge, the `<run>` of its ad-hoc
/// ids ([`ad_hoc_location_id`]). `RandomState`'s keys come from the
/// system's random source; the time and the process id are hashed with them.
fn new_run() -> u64 {
    RandomState::new().hash_one((SystemTime::now(), std::process::id()))
}

/// `Unsupported`: the backend package is missing (XP-5).
#[must_use]
pub fn no_backend(provider: &str) -> Status {
    Status::new(ErrorName::Unsupported, format!("No backend for {provider} is installed"))
}

impl<B: Backend> LocationBook<B> {
    /// An empty book over `pools`, for one run of the bridge.
    #[must_use]
    pub fn new(pools: PoolSet<B>) -> Self {
        Self {
            accounts: Vec::new(),
            ad_hoc: BTreeMap::new(),
            connecting: BTreeMap::new(),
            run: new_run(),
            next_ad_hoc: 1,
            pools,
        }
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

    /// Takes the account list (`load`, `refresh`): pools of accounts that
    /// are gone or now connect differently are dropped, so that new
    /// connections use the new settings. The caller broadcasts
    /// `LocationsChanged` when consent is granted.
    pub fn set_accounts(&mut self, accounts: Vec<LocationSpec>) {
        let accounts: Vec<Arc<LocationSpec>> = accounts.into_iter().map(Arc::new).collect();
        self.pools.retain(|pool| {
            pool.account_id().is_none()
                || accounts.iter().any(|a| a.id == pool.id && a.same_connection(&pool.params))
        });
        self.accounts = accounts;
    }

    /// Consent was revoked (XB-6): every pool goes, ad-hoc secrets are
    /// wiped and ad-hoc locations forgotten.
    pub fn revoke(&mut self) {
        self.pools.clear();
        self.wipe_ad_hoc_secrets();
        self.ad_hoc.clear();
        self.connecting.clear();
    }

    fn wipe_ad_hoc_secrets(&self) {
        for spec in self.ad_hoc.values().chain(self.connecting.values()) {
            if let Some(secret) = &spec.ad_hoc_secret {
                secret.wipe();
            }
        }
    }

    /// Wakes every running item to look at its cancel flag (`kickAll`).
    pub fn kick(&mut self) {
        self.pools.kick();
    }

    /// Closes connections idle for `idle` (and frees finished ones):
    /// whether anything changed.
    pub fn maintain(&mut self, now: Instant, idle: Duration) -> bool {
        self.pools.maintain(now, idle)
    }

    /// What `ListLocations` shows: the accounts, then the ad-hoc
    /// locations by id.
    pub fn visible(&self) -> impl Iterator<Item = &Arc<LocationSpec>> {
        self.accounts.iter().chain(self.ad_hoc.values())
    }

    /// The location `id`, if the consumer can see it.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&Arc<LocationSpec>> {
        self.accounts.iter().find(|a| a.id == id).or_else(|| self.ad_hoc.get(id))
    }

    /// Whether the visible location `id` has a pool (`existing`).
    #[must_use]
    pub fn has_pool(&self, id: &str) -> bool {
        !self.connecting.contains_key(id) && self.pools.get(id).is_some()
    }

    /// Makes sure the location `id` has a pool (`pool`), for a call that
    /// needs a connection.
    ///
    /// # Errors
    /// `PermissionDenied` without consent, `NotFound` for an unknown id,
    /// `Unsupported` when the provider's backend is missing.
    pub fn ensure_pool(
        &mut self,
        id: &str,
        consent_granted: bool,
        provider_available: impl FnOnce(&str) -> bool,
    ) -> Result<&Arc<LocationSpec>, Status> {
        if !consent_granted {
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

    /// The id of the next ad-hoc location (`reserveAdHocId`): never one
    /// given out before, by this book or by an earlier run's.
    pub fn reserve_ad_hoc_id(&mut self) -> String {
        let id = ad_hoc_location_id(self.run, self.next_ad_hoc);
        self.next_ad_hoc = self.next_ad_hoc.saturating_add(1);
        id
    }

    /// Starts an ad-hoc location (`connectAdHoc`): its pool exists from
    /// now on, unseen; the core then submits an empty item on
    /// [`Lane::Interactive`] (establishing is what the first item does) and
    /// ends with [`LocationBook::add_ad_hoc`] or
    /// [`LocationBook::abandon_ad_hoc`]. False if the id is taken.
    pub fn start_ad_hoc(&mut self, spec: LocationSpec) -> bool {
        if spec.kind != LocationKind::AdHoc
            || self.find(&spec.id).is_some()
            || self.pools.get(&spec.id).is_some()
        {
            return false;
        }
        let spec = Arc::new(spec);
        self.pools.add(Arc::clone(&spec));
        self.connecting.insert(spec.id.clone(), spec);
        true
    }

    /// The first connection of the ad-hoc location `id` was established:
    /// it becomes visible (the caller broadcasts `LocationsChanged`).
    /// False when it is no longer being connected (revoked meanwhile).
    pub fn add_ad_hoc(&mut self, id: &str) -> bool {
        let Some(spec) = self.connecting.remove(id) else { return false };
        if self.pools.get(id).is_none() {
            return false;
        }
        self.ad_hoc.insert(spec.id.clone(), spec);
        true
    }

    /// The first connection of the ad-hoc location `id` failed: its pool
    /// goes and its secret is wiped.
    pub fn abandon_ad_hoc(&mut self, id: &str) {
        if let Some(spec) = self.connecting.remove(id) {
            if let Some(secret) = &spec.ad_hoc_secret {
                secret.wipe();
            }
            self.pools.remove(id);
        }
    }

    /// `ForgetAdHoc` (XB-14): drops the pin, so the next contact asks
    /// again, wipes the secret and closes the connections. False for an
    /// unknown id (the caller replies `NotFound`; the caller broadcasts
    /// `LocationsChanged` otherwise).
    pub fn forget_ad_hoc(&mut self, id: &str, pins: &dyn PinStore) -> bool {
        let Some(spec) = self.ad_hoc.remove(id) else { return false };
        // False only means there was no pin.
        let _had_pin = pins.remove(&spec.host_key());
        if let Some(secret) = &spec.ad_hoc_secret {
            secret.wipe();
        }
        self.pools.remove(id);
        true
    }

    /// `Disconnect`: stops every connection of `id`.
    pub fn disconnect(&mut self, id: &str) {
        if self.has_pool(id) {
            self.pools.stop_all(id);
        }
    }

    /// Closes read handle `handle` on the connection `worker` of `loc`
    /// (`closeWorkerHandle`); nothing when the connection is gone, its
    /// handles went with it.
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

impl<B: Backend> Drop for LocationBook<B> {
    fn drop(&mut self) {
        self.wipe_ad_hoc_secrets();
    }
}

#[cfg(test)]
#[path = "book_tests.rs"]
mod tests;
