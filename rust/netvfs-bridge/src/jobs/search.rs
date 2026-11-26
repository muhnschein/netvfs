// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `Search` body: what the server finds streams in `WalkBatch` signals, each entry with its path below the root. `JobFinished` carries `entries`, the number sent.

use super::JobOutcome;
use super::walk::stream;
use crate::access::is_folder;
use crate::ffi::Conn;
use crate::server::FlowBudget;
use crate::status::Status;
use netvfs_bridge_proto::{WireEntry, WireWalkItem};
use std::sync::atomic::AtomicBool;

/// What `Search` needs of a connection.
pub trait Searcher {
    /// The entries below `root` whose name holds `text`, `limit` at most, batch by batch, each named by its path below `root`; `sink` returns false to stop.
    ///
    /// # Errors
    /// The backend's failure.
    fn search(
        &mut self,
        root: &[u8],
        text: &str,
        limit: u32,
        sink: &mut dyn FnMut(&[WireEntry]) -> bool,
    ) -> Result<(), Status>;
}

impl Searcher for Conn {
    fn search(
        &mut self,
        root: &[u8],
        text: &str,
        limit: u32,
        sink: &mut dyn FnMut(&[WireEntry]) -> bool,
    ) -> Result<(), Status> {
        Self::search(self, root, text, limit, sink)
    }
}

/// A found entry as `WalkBatch` carries it: the path below the root, and the entry under its own name. `None` for a path that is empty or has a `.`, `..` or empty component.
#[must_use]
pub fn found_item(found: &WireEntry) -> Option<WireWalkItem> {
    let path = found.name.as_slice();
    let fine = |part: &[u8]| !part.is_empty() && part != b"." && part != b"..";
    if path.is_empty() || !path.split(|b| *b == b'/').all(fine) {
        return None;
    }
    let name = path.rsplit(|b| *b == b'/').next().unwrap_or(path).to_vec();
    Some(WireWalkItem { path: path.to_vec(), entry: WireEntry { name, ..found.clone() } })
}

/// Searches below `root` and hands every batch to `emit` (see [`super::walk::walk_batches`]), folders only when `folders_only`.
pub fn search<S: Searcher + ?Sized, E: FnMut(Vec<WireWalkItem>, usize) -> bool>(
    searcher: &mut S,
    (root, text, limit, folders_only): (&[u8], &str, u32, bool),
    budget: &FlowBudget,
    cancel: &AtomicBool,
    emit: E,
) -> JobOutcome {
    stream(budget, cancel, emit, |visit| {
        searcher.search(root, text, limit, &mut |entries: &[WireEntry]| {
            entries
                .iter()
                .filter(|e| !folders_only || is_folder(e.kind, e.target_kind))
                .filter_map(found_item)
                .all(|item| visit(&item.path, item.entry))
        })
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    use super::*;
    use netvfs_bridge_proto::ErrorName;
    use netvfs_bridge_proto::wire::entry_kind;

    struct Found(Vec<WireEntry>, Vec<(Vec<u8>, String, u32)>, Option<ErrorName>);

    impl Searcher for Found {
        fn search(
            &mut self,
            root: &[u8],
            text: &str,
            limit: u32,
            sink: &mut dyn FnMut(&[WireEntry]) -> bool,
        ) -> Result<(), Status> {
            self.1.push((root.to_vec(), text.to_owned(), limit));
            if let Some(name) = self.2 {
                return Err(Status::new(name, "no"));
            }
            for batch in self.0.chunks(2) {
                if !sink(batch) {
                    return Err(crate::locations::canceled());
                }
            }
            Ok(())
        }
    }

    fn run(found: &mut Found, folders_only: bool) -> (JobOutcome, Vec<WireWalkItem>) {
        let budget = FlowBudget::new(usize::MAX);
        let cancel = AtomicBool::new(false);
        let mut items = Vec::new();
        let outcome = search(found, (b"docs", "tax", 7, folders_only), &budget, &cancel, |batch, _| {
            items.extend(batch);
            true
        });
        (outcome, items)
    }

    fn entries() -> Vec<WireEntry> {
        vec![
            WireEntry::unknown(b"Tax", entry_kind::DIRECTORY),
            WireEntry::unknown(b"Tax/deep/tax-2026.pdf", entry_kind::FILE),
            WireEntry::unknown(b"../escape", entry_kind::FILE),
            WireEntry::unknown(b"a//b", entry_kind::FILE),
            WireEntry::unknown(b"", entry_kind::FILE),
            WireEntry::unknown(b"/abs", entry_kind::FILE),
            WireEntry::unknown(b"taxes.txt", entry_kind::FILE),
        ]
    }

    #[test]
    fn found_entries_carry_their_path_and_own_name() {
        let mut found = Found(entries(), Vec::new(), None);
        let (outcome, items) = run(&mut found, false);
        assert!(outcome.result.is_ok());
        assert_eq!(found.1, [(b"docs".to_vec(), "tax".to_owned(), 7)]);
        let seen: Vec<(&[u8], &[u8], u8)> =
            items.iter().map(|i| (i.path.as_slice(), i.entry.name.as_slice(), i.entry.kind)).collect();
        assert_eq!(
            seen,
            [
                (&b"Tax"[..], &b"Tax"[..], entry_kind::DIRECTORY),
                (&b"Tax/deep/tax-2026.pdf"[..], &b"tax-2026.pdf"[..], entry_kind::FILE),
                (&b"taxes.txt"[..], &b"taxes.txt"[..], entry_kind::FILE),
            ],
            "paths that leave the root or are malformed are dropped"
        );
        assert_eq!(i64::try_from(&outcome.extra["entries"]).unwrap(), 3);
    }

    #[test]
    fn add_access_finds_folders_only_and_failures_end_the_job() {
        let mut found = Found(entries(), Vec::new(), None);
        let (_, items) = run(&mut found, true);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path, b"Tax");
        let mut failing = Found(entries(), Vec::new(), Some(ErrorName::Unsupported));
        let (outcome, items) = run(&mut failing, false);
        assert_eq!(outcome.result.unwrap_err().name, ErrorName::Unsupported);
        assert!(items.is_empty());
        let budget = FlowBudget::new(usize::MAX);
        let cancel = AtomicBool::new(true);
        let mut stopped = Found(entries(), Vec::new(), None);
        let outcome = search(&mut stopped, (b"", "x", 1, false), &budget, &cancel, |_, _| true);
        assert_eq!(outcome.result.unwrap_err().name, ErrorName::Canceled);
    }

    #[test]
    fn items_need_a_clean_relative_path() {
        let item = |path: &[u8]| found_item(&WireEntry::unknown(path, entry_kind::FILE));
        assert_eq!(item(b"a").unwrap().entry.name, b"a");
        assert_eq!(item(b"a/b c/d").unwrap().entry.name, b"d");
        for bad in [&b""[..], b"/", b"/a", b"a/", b"a//b", b".", b"..", b"a/./b", b"a/../b"] {
            assert!(item(bad).is_none(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
