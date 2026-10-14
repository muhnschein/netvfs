// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bodies of requests and jobs that run on a worker thread, with the
//! worker's connection (sessionfiles.cpp `listOnWorker`, sessionjobs.cpp
//! `transferOnWorker`, `walkOnWorker`, `removeTreeOnWorker`), and the
//! checks and local I/O of transferred descriptors (fdcheck.cpp, XB-11).
//!
//! The core (chunk E) submits a body as a [`Work`](crate::locations::worker::Work)
//! item; the body streams `ListBatch` / `WalkBatch` straight to the
//! session's outbox under its flow budget ([`batch`]), reports progress
//! through a [`progress::JobProgress`] and returns a [`JobOutcome`] for
//! `ListDone` / `JobFinished`, which the core sends.

pub mod batch;
pub mod fd;
pub mod fdio;
pub mod progress;
pub mod remove;
pub mod transfer;
pub mod walk;

use crate::status::Status;
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;

/// The `extra` of `JobFinished`: `entries`, `files`, `dirs`, `bytes`.
pub type Extra = HashMap<String, OwnedValue>;

/// How a job ended: its result and its `extra`.
#[derive(Debug, PartialEq)]
pub struct JobOutcome {
    /// The result.
    pub result: Result<(), Status>,
    /// What `JobFinished` carries besides the result.
    pub extra: Extra,
}

impl JobOutcome {
    /// An outcome without extra values (a job that could not start).
    #[must_use]
    pub fn failed(status: Status) -> Self {
        Self { result: Err(status), extra: Extra::new() }
    }

    /// The outcome as `runJob` reports it: a failure of a canceled job is
    /// `Canceled` (a local write failing because of the cancel).
    #[must_use]
    pub fn settle(self, canceled: bool) -> Self {
        Self { result: settle(self.result, canceled), extra: self.extra }
    }
}

/// `result`, or `Canceled` when it failed while `canceled` was set.
///
/// # Errors
/// `result`'s failure, or `Canceled`.
pub fn settle(result: Result<(), Status>, canceled: bool) -> Result<(), Status> {
    match result {
        Err(_) if canceled => Err(crate::locations::canceled()),
        other => other,
    }
}

/// An `extra` value of a count.
fn count(n: i64) -> OwnedValue {
    OwnedValue::from(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_result_states)]
    use super::*;
    use netvfs_bridge_proto::ErrorName;

    #[test]
    fn settle_turns_failures_of_canceled_jobs_into_canceled() {
        let lost = || Err(Status::new(ErrorName::ConnectionLost, "x"));
        assert_eq!(settle(lost(), false), lost());
        assert_eq!(settle(lost(), true), Err(crate::locations::canceled()));
        assert_eq!(settle(Ok(()), true), Ok(()));
        let mut extra = Extra::new();
        extra.insert("bytes".into(), count(3));
        let outcome = JobOutcome { result: lost(), extra: extra.clone() }.settle(true);
        assert_eq!(outcome, JobOutcome { result: Err(crate::locations::canceled()), extra });
        let failed = JobOutcome::failed(Status::new(ErrorName::NotFound, "n"));
        assert!(failed.extra.is_empty());
        assert_eq!(failed.result.unwrap_err().name, ErrorName::NotFound);
    }
}
