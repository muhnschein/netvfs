// SPDX-License-Identifier: LGPL-2.1-or-later
//! XB-17: what one consumer may have in flight (`ConsumerQuota` of
//! serverparts.cpp): 64 requests, 16 open files and 8 jobs. Above a limit
//! a call fails with `TooManyConnections` and `retryAfterMs` 1000. The
//! core re-evaluates the idle exit after every change (XB-2).

use crate::Status;
use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::limits::{MAX_HANDLES, MAX_JOBS, MAX_REQUESTS, RETRY_AFTER_MS};

/// `TooManyConnections` with `message` and the retry time (XB-17).
#[must_use]
pub fn too_many(message: &str) -> Status {
    Status::new(ErrorName::TooManyConnections, message)
        .with_retry_after_ms(i64::try_from(RETRY_AFTER_MS).unwrap_or(i64::MAX))
}

/// One counter with its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counter {
    used: usize,
    limit: usize,
}

impl Counter {
    const fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    fn acquire(&mut self) -> bool {
        if self.used >= self.limit {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }

    fn release(&mut self) {
        self.used = self.used.saturating_sub(1);
    }
}

/// The requests, open files and jobs of the consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    requests: Counter,
    handles: Counter,
    jobs: Counter,
}

impl Default for Quota {
    fn default() -> Self {
        Self::new(MAX_REQUESTS, MAX_HANDLES, MAX_JOBS)
    }
}

impl Quota {
    /// A quota of `requests`, `handles` and `jobs`.
    #[must_use]
    pub const fn new(requests: usize, handles: usize, jobs: usize) -> Self {
        Self { requests: Counter::new(requests), handles: Counter::new(handles), jobs: Counter::new(jobs) }
    }

    /// Takes a request slot; false at the limit.
    pub fn acquire_request(&mut self) -> bool {
        self.requests.acquire()
    }

    /// Gives a request slot back.
    pub fn release_request(&mut self) {
        self.requests.release();
    }

    /// Takes an open-file slot; false at the limit.
    pub fn acquire_handle(&mut self) -> bool {
        self.handles.acquire()
    }

    /// Gives an open-file slot back.
    pub fn release_handle(&mut self) {
        self.handles.release();
    }

    /// Takes a job slot; false at the limit.
    pub fn acquire_job(&mut self) -> bool {
        self.jobs.acquire()
    }

    /// Gives a job slot back.
    pub fn release_job(&mut self) {
        self.jobs.release();
    }

    /// Requests in flight.
    #[must_use]
    pub const fn active_requests(&self) -> usize {
        self.requests.used
    }

    /// Open read handles.
    #[must_use]
    pub const fn open_handles(&self) -> usize {
        self.handles.used
    }

    /// Running jobs.
    #[must_use]
    pub const fn running_jobs(&self) -> usize {
        self.jobs.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_of_a_consumer() {
        let mut q = Quota::default();
        for _ in 0..MAX_REQUESTS {
            assert!(q.acquire_request());
        }
        assert!(!q.acquire_request());
        assert_eq!(q.active_requests(), MAX_REQUESTS);
        for _ in 0..MAX_HANDLES {
            assert!(q.acquire_handle());
        }
        assert!(!q.acquire_handle());
        for _ in 0..MAX_JOBS {
            assert!(q.acquire_job());
        }
        assert!(!q.acquire_job());
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (64, 16, 8));
        q.release_request();
        q.release_handle();
        q.release_job();
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (63, 15, 7));
        assert!(q.acquire_request() && q.acquire_handle() && q.acquire_job());
    }

    #[test]
    fn counters_are_separate_and_never_negative() {
        let mut q = Quota::new(1, 2, 3);
        q.release_request();
        q.release_handle();
        q.release_job();
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (0, 0, 0));
        assert!(q.acquire_request());
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (1, 0, 0));
        assert!(q.acquire_handle());
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (1, 1, 0));
        assert!(q.acquire_job());
        assert_eq!((q.active_requests(), q.open_handles(), q.running_jobs()), (1, 1, 1));
        assert!(!q.acquire_request());
        assert!(q.acquire_handle() && !q.acquire_handle());
        assert!(q.acquire_job() && q.acquire_job() && !q.acquire_job());
        assert!(!Quota::new(0, 0, 0).acquire_job());
    }

    #[test]
    fn too_many_carries_the_retry_time() {
        let s = too_many("Too many requests");
        assert_eq!(s.name, ErrorName::TooManyConnections);
        assert_eq!(s.message, "Too many requests");
        assert_eq!(s.retry_after_ms, 1000);
    }
}
