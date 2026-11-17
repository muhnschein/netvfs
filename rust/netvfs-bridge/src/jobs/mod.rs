// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bodies of requests and jobs that run on a worker thread with the worker's connection, and the checks and local I/O of transferred descriptors.
//!
//! The core submits a body as a [`Work`](crate::locations::worker::Work) item; the body streams `ListBatch` / `WalkBatch` to the session's outbox under its flow budget ([`batch`]), reports progress through a [`progress::JobProgress`] and returns a [`JobOutcome`] for `ListDone` / `JobFinished`, which the core sends.

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

/// The `extra` of `JobFinished`.
pub type Extra = HashMap<String, OwnedValue>;

/// How a job ended.
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

    /// The outcome, `Canceled` if the job failed while `canceled`.
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
