// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
use super::*;
use crate::server::paths::normalize;
use netvfs_bridge_proto::ErrorName;
use netvfs_bridge_proto::limits::CHECK_RACY_MS;
use netvfs_bridge_proto::wire::entry_kind;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

const NOW: i64 = 1_800_000_000_000;
const OLD: i64 = 1_700_000_000_000;

#[derive(Default)]
struct Tree {
    folders: HashMap<Vec<u8>, (WireEntry, Vec<WireEntry>)>,
    lists: Vec<Vec<u8>>,
}

impl Tree {
    fn folder(mut self, path: &str, etag: &str, mtime_ms: i64, children: usize) -> Self {
        let mut entry =
            WireEntry::unknown(path.rsplit('/').next().unwrap().as_bytes(), entry_kind::DIRECTORY);
        entry.etag = etag.as_bytes().to_vec();
        entry.mtime_ms = mtime_ms;
        let mut kids: Vec<WireEntry> =
            (0..children).map(|i| WireEntry::unknown(format!("f{i}").as_bytes(), entry_kind::FILE)).collect();
        kids.push(WireEntry::unknown(b"sub", entry_kind::DIRECTORY));
        self.folders.insert(path.as_bytes().to_vec(), (entry, kids));
        self
    }
}

impl Folders for Tree {
    fn stat(&mut self, path: &[u8]) -> Result<WireEntry, Status> {
        self.folders.get(path).map(|f| f.0.clone()).ok_or_else(|| Status::new(ErrorName::NotFound, "gone"))
    }

    fn list(&mut self, path: &[u8], sink: &mut dyn FnMut(&[WireEntry]) -> bool) -> Result<(), Status> {
        self.lists.push(path.to_vec());
        let kids = self.folders.get(path).map(|f| f.1.clone()).unwrap_or_default();
        for chunk in kids.chunks(100) {
            if !sink(chunk) {
                return Err(crate::locations::canceled());
            }
        }
        Ok(())
    }
}

fn item(path: &str, etag: &str, mtime_ms: Option<i64>) -> CheckItem {
    CheckItem { path: normalize(path.as_bytes()).unwrap(), etag: etag.as_bytes().to_vec(), mtime_ms }
}

fn run(tree: &mut Tree, items: &[CheckItem], folders_only: bool) -> (JobOutcome, Vec<WireCheckResult>) {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut results = Vec::new();
    let only = vec![folders_only; items.len()];
    let outcome = check(tree, (items, &only, NOW), &budget, &cancel, |batch: Vec<WireCheckResult>, _| {
        results.extend(batch);
        true
    });
    (outcome, results)
}

fn extra(outcome: &JobOutcome, key: &str) -> i64 {
    i64::try_from(&outcome.extra[key]).unwrap()
}

#[test]
fn an_etag_decides_when_the_folder_has_one() {
    let entry = |etag: &str, mtime_ms| {
        let mut e = WireEntry::unknown(b"d", entry_kind::DIRECTORY);
        e.etag = etag.as_bytes().to_vec();
        e.mtime_ms = mtime_ms;
        e
    };
    assert!(
        !changed(&item("d", "e1", None), &entry("e1", NOW), NOW),
        "a fresh date does not matter with an etag"
    );
    assert!(changed(&item("d", "e1", Some(OLD)), &entry("e2", OLD), NOW));
    assert!(!changed(&item("d", "", Some(OLD)), &entry("", OLD), NOW));
    assert!(changed(&item("d", "", Some(OLD)), &entry("", OLD + 1), NOW));
    assert!(changed(&item("d", "", None), &entry("", OLD), NOW));
    assert!(changed(&item("d", "", Some(-1)), &entry("", -1), NOW), "an unknown date is never unchanged");
    let racy = NOW - CHECK_RACY_MS + 1;
    assert!(changed(&item("d", "", Some(racy)), &entry("", racy), NOW), "a date under 2 s old");
    let settled = NOW - CHECK_RACY_MS;
    assert!(!changed(&item("d", "", Some(settled)), &entry("", settled), NOW));
}

#[test]
fn only_changed_folders_are_listed_in_the_order_asked() {
    let mut tree = Tree::default().folder("a", "", OLD, 2).folder("b", "", OLD, 2).folder("c", "x", OLD, 1);
    let items = [item("a", "", Some(OLD)), item("b", "", Some(OLD - 5)), item("c", "x", None)];
    let (outcome, results) = run(&mut tree, &items, false);
    assert!(outcome.result.is_ok());
    assert_eq!((extra(&outcome, "folders"), extra(&outcome, "listed")), (3, 1));
    assert_eq!(tree.lists, [b"b".to_vec()]);
    let summary: Vec<(u32, bool, usize)> =
        results.iter().map(|r| (r.index, r.listed, r.children.len())).collect();
    assert_eq!(summary, [(0, false, 0), (1, true, 3), (2, false, 0)]);
    assert_eq!(results[1].entry.mtime_ms, OLD);
    assert!(results.iter().all(|r| r.error.is_empty()));
}

#[test]
fn a_missing_folder_is_reported_and_the_rest_checked() {
    let mut tree = Tree::default().folder("b", "", OLD, 0);
    let (outcome, results) = run(&mut tree, &[item("gone", "", None), item("b", "", None)], false);
    assert!(outcome.result.is_ok());
    assert_eq!(extra(&outcome, "folders"), 2);
    assert_eq!((results[0].error.as_str(), results[0].listed), ("NotFound", false));
    assert_eq!((results[1].error.as_str(), results[1].listed), ("", true));
}

#[test]
fn a_long_listing_spans_results_and_add_access_sees_folders_only() {
    let mut tree = Tree::default().folder("big", "", OLD, 1200);
    let (outcome, results) = run(&mut tree, &[item("big", "", None)], false);
    assert!(outcome.result.is_ok());
    let sizes: Vec<usize> = results.iter().map(|r| r.children.len()).collect();
    assert_eq!(sizes, [512, 512, 177]);
    assert!(results.iter().all(|r| r.index == 0 && r.listed));
    let (_, results) = run(&mut tree, &[item("big", "", None)], true);
    assert_eq!(results.len(), 1);
    let names: Vec<&[u8]> = results[0].children.iter().map(|e| e.name.as_slice()).collect();
    assert_eq!(names, [&b"sub"[..]]);
}

#[test]
fn an_empty_changed_folder_still_reports_one_listed_result() {
    let mut tree = Tree::default();
    tree.folders.insert(b"e".to_vec(), (WireEntry::unknown(b"e", entry_kind::DIRECTORY), Vec::new()));
    let (_, results) = run(&mut tree, &[item("e", "", None)], false);
    assert_eq!(results.len(), 1);
    assert!(results[0].listed && results[0].children.is_empty());
}

#[test]
fn results_go_out_in_batches_and_a_stop_ends_the_job() {
    let mut tree = Tree::default();
    let mut items = Vec::new();
    for i in 0..100 {
        let p = format!("d{i}");
        tree = tree.folder(&p, "", OLD, 0);
        items.push(item(&p, "", Some(OLD)));
    }
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sizes = Vec::new();
    let outcome =
        check(&mut tree, (&items, &[false; 100], NOW), &budget, &cancel, |b: Vec<WireCheckResult>, bytes| {
            assert!(bytes >= b.len() * RESULT_FIXED_BYTES);
            sizes.push(b.len());
            true
        });
    assert!(outcome.result.is_ok());
    assert_eq!(sizes, [64, 36]);
    let mut calls = 0;
    let outcome =
        check(&mut tree, (&items, &[false; 100], NOW), &budget, &cancel, |_: Vec<WireCheckResult>, _| {
            calls += 1;
            false
        });
    assert_eq!(outcome.result.unwrap_err().name, ErrorName::Canceled);
    assert_eq!(calls, 1);
    cancel.store(true, Ordering::Release);
    let outcome =
        check(&mut tree, (&items, &[false; 100], NOW), &budget, &cancel, |_: Vec<WireCheckResult>, _| true);
    assert_eq!(outcome.result.unwrap_err().name, ErrorName::Canceled);
}

#[test]
fn result_size_counts_path_error_and_every_entry() {
    let e = WireEntry::unknown(b"abc", entry_kind::FILE);
    let r = WireCheckResult {
        index: 0,
        error: "NotFound".to_owned(),
        entry: e.clone(),
        listed: true,
        children: vec![e.clone(), e.clone()],
    };
    assert_eq!(result_wire_size(&r), RESULT_FIXED_BYTES + 3 * entry_wire_size(&e) + 8);
}
