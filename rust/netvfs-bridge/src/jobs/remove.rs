// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `RemoveTree` body (`removeTreeOnWorker`): progress counts files
//! and folders removed; `JobFinished` carries `files` and `dirs`, also
//! after a failure.

use super::progress::JobProgress;
use super::{Extra, JobOutcome, count};
use crate::ffi::{Conn, TreeCounts};
use std::sync::atomic::AtomicBool;

/// `files` and `dirs` of `JobFinished`.
#[must_use]
pub fn tree_extra(counts: TreeCounts) -> Extra {
    let mut extra = Extra::new();
    extra.insert("files".to_owned(), count(counts.files));
    extra.insert("dirs".to_owned(), count(counts.dirs));
    extra
}

/// Removes `path` and everything below it; `report` gets the progress.
pub fn remove_tree<F: FnMut(i64, i64)>(
    conn: &mut Conn,
    path: &[u8],
    cancel: &AtomicBool,
    report: F,
) -> JobOutcome {
    let mut progress = JobProgress::new(cancel, report);
    let (counts, result) = conn.remove_tree(path, Some(&mut progress));
    JobOutcome { result, extra: tree_extra(counts) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_counts_files_and_folders() {
        let extra = tree_extra(TreeCounts { files: 3, dirs: 2 });
        assert_eq!(extra.len(), 2);
        assert_eq!(i64::try_from(&extra["files"]).unwrap(), 3);
        assert_eq!(i64::try_from(&extra["dirs"]).unwrap(), 2);
    }
}
