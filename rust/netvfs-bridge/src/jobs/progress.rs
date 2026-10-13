// SPDX-License-Identifier: LGPL-2.1-or-later
//! Progress of a job (`JobProgressSink` of sessionjobs.cpp): updates pass at
//! most every 250 ms (XB-10, `JobProgress` at most 4 Hz), and the job's
//! cancel flag answers [`Progress::canceled`].

use crate::ffi::Progress;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The shortest time between two reported updates.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// Hands a job's progress to `report` (which sends `JobProgress`), at most
/// every [`PROGRESS_INTERVAL`]; the first update always passes.
pub struct JobProgress<'a, F: FnMut(i64, i64)> {
    report: F,
    cancel: &'a AtomicBool,
    last: Option<Instant>,
}

impl<F: FnMut(i64, i64)> fmt::Debug for JobProgress<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobProgress").field("last", &self.last).finish_non_exhaustive()
    }
}

impl<'a, F: FnMut(i64, i64)> JobProgress<'a, F> {
    /// Progress of the job whose cancel flag is `cancel`.
    pub const fn new(cancel: &'a AtomicBool, report: F) -> Self {
        Self { report, cancel, last: None }
    }

    /// [`Progress::update`] at time `now`.
    fn update_at(&mut self, now: Instant, done: i64, total: i64) {
        if self.last.is_some_and(|last| now.saturating_duration_since(last) < PROGRESS_INTERVAL) {
            return;
        }
        self.last = Some(now);
        (self.report)(done, total);
    }
}

impl<F: FnMut(i64, i64)> Progress for JobProgress<'_, F> {
    fn update(&mut self, done: i64, total: i64) {
        self.update_at(Instant::now(), done, total);
    }

    fn canceled(&mut self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_pass_at_most_every_interval() {
        let cancel = AtomicBool::new(false);
        let mut seen = Vec::new();
        let mut progress = JobProgress::new(&cancel, |done, total| seen.push((done, total)));
        let t0 = Instant::now();
        progress.update_at(t0, 1, 10);
        progress.update_at(t0 + Duration::from_millis(249), 2, 10);
        progress.update_at(t0 + PROGRESS_INTERVAL, 3, 10);
        progress.update_at(t0 + Duration::from_millis(400), 4, 10);
        progress.update_at(t0 + Duration::from_millis(501), 5, -1);
        // A clock that went back does not report.
        progress.update_at(t0, 6, -1);
        assert!(format!("{progress:?}").starts_with("JobProgress"));
        assert_eq!(seen, [(1, 10), (3, 10), (5, -1)]);
    }

    #[test]
    fn the_first_real_update_passes_and_cancel_is_the_flag() {
        let cancel = AtomicBool::new(false);
        let mut seen = 0;
        let mut progress = JobProgress::new(&cancel, |_, _| seen += 1);
        progress.update(1, 2);
        progress.update(2, 2);
        assert!(!progress.canceled());
        cancel.store(true, Ordering::Release);
        assert!(progress.canceled());
        assert_eq!(seen, 1);
    }
}
