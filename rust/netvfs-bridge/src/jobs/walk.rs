// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `Walk` body: entries stream in `WalkBatch` signals of at most [`MAX_LIST_BATCH`] items; unreadable sub-folders are skipped, as a file browser expects. `JobFinished` carries `entries`, the number sent.

use super::batch::{Batcher, drain, walk_item_wire_size};
use super::{Extra, JobOutcome, count};
use crate::ffi::{Conn, WalkOptions};
use crate::server::args::WalkOpts;
use crate::server::encode::OutSignal;
use crate::server::{FlowBudget, Outbox};
use crate::status::Status;
use netvfs_bridge_proto::limits::MAX_LIST_BATCH;
use netvfs_bridge_proto::{WireEntry, WireWalkItem};
use std::sync::atomic::AtomicBool;

/// The backend's walk options for `opts`; negative depth: unlimited.
#[must_use]
pub fn walk_options(opts: &WalkOpts) -> WalkOptions {
    WalkOptions {
        max_depth: u32::try_from(opts.max_depth).ok(),
        follow_symlinks: opts.follow_symlinks,
        post_order: opts.post_order,
        stop_on_list_error: false,
    }
}

/// `entries` of `JobFinished`.
#[must_use]
pub fn walk_extra(entries: i64) -> Extra {
    let mut extra = Extra::new();
    extra.insert("entries".to_owned(), count(entries));
    extra
}

fn stream<E: FnMut(Vec<WireWalkItem>, usize) -> bool>(
    budget: &FlowBudget,
    cancel: &AtomicBool,
    mut emit: E,
    run: impl FnOnce(&mut dyn FnMut(&[u8], WireEntry) -> bool) -> Result<(), Status>,
) -> JobOutcome {
    let mut entries = 0_i64;
    let counted = |items: Vec<WireWalkItem>, bytes| {
        entries = entries.saturating_add(i64::try_from(items.len()).unwrap_or(i64::MAX));
        emit(items, bytes)
    };
    let max_items = usize::try_from(MAX_LIST_BATCH).unwrap_or(usize::MAX);
    let mut batcher = Batcher::new(max_items, walk_item_wire_size, counted, budget, cancel);
    let result =
        drain(&mut batcher, |b| run(&mut |path, entry| b.add(WireWalkItem { path: path.to_vec(), entry })));
    drop(batcher);
    JobOutcome { result, extra: walk_extra(entries) }
}

/// Walks the tree at `root` and hands every batch to `emit` (see [`walk_batches`]).
pub fn walk<E: FnMut(Vec<WireWalkItem>, usize) -> bool>(
    conn: &mut Conn,
    root: &[u8],
    opts: &WalkOpts,
    budget: &FlowBudget,
    cancel: &AtomicBool,
    emit: E,
) -> JobOutcome {
    let options = walk_options(opts);
    stream(budget, cancel, emit, |visit| conn.walk(root, &options, visit))
}

/// An emitter of `WalkBatch` signals of job `job` on `outbox`.
pub fn walk_batches(outbox: &Outbox, job: u32) -> impl FnMut(Vec<WireWalkItem>, usize) -> bool + '_ {
    move |items, bytes| outbox.send_streamed(&OutSignal::WalkBatch { job, items }, bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]
    use super::*;
    use crate::server::SessionId;
    use crate::server::flow::{Link, outbox};
    use netvfs_bridge_proto::ErrorName;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn options_follow_the_call() {
        let o = walk_options(&WalkOpts { max_depth: -1, follow_symlinks: true, post_order: false });
        assert_eq!(
            o,
            WalkOptions {
                max_depth: None,
                follow_symlinks: true,
                post_order: false,
                stop_on_list_error: false
            }
        );
        let o = walk_options(&WalkOpts { max_depth: 0, follow_symlinks: false, post_order: true });
        assert_eq!((o.max_depth, o.follow_symlinks, o.post_order), (Some(0), false, true));
        assert_eq!(walk_options(&WalkOpts { max_depth: 7, ..WalkOpts::default() }).max_depth, Some(7));
    }

    type Visit<'a> = &'a mut dyn FnMut(&[u8], WireEntry) -> bool;

    fn visit_n(n: usize) -> impl FnOnce(Visit<'_>) -> Result<(), Status> {
        move |visit| {
            for i in 0..n {
                let name = format!("f{i}");
                if !visit(format!("d/{name}").as_bytes(), WireEntry::unknown(name.as_bytes(), 1)) {
                    return Err(crate::locations::canceled());
                }
            }
            Ok(())
        }
    }

    #[test]
    fn walks_stream_in_batches_and_count_what_was_sent() {
        let budget = FlowBudget::new(usize::MAX);
        let cancel = AtomicBool::new(false);
        let mut sizes = Vec::new();
        let mut first = None;
        let outcome = stream(
            &budget,
            &cancel,
            |items: Vec<WireWalkItem>, bytes| {
                first.get_or_insert_with(|| (items[0].path.clone(), bytes, items[0].entry.name.clone()));
                sizes.push(items.len());
                true
            },
            visit_n(1100),
        );
        assert!(outcome.result.is_ok());
        assert_eq!(i64::try_from(&outcome.extra["entries"]).unwrap(), 1100);
        assert_eq!(sizes, [512, 512, 76]);
        let (path, bytes, name) = first.unwrap();
        assert_eq!((path.as_slice(), name.as_slice()), (&b"d/f0"[..], &b"f0"[..]));
        assert!(bytes > 512 * 96);
    }

    #[test]
    fn a_stopped_walk_counts_only_what_went_out() {
        let budget = FlowBudget::new(usize::MAX);
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let outcome = stream(
            &budget,
            &cancel,
            |_, _| {
                calls += 1;
                calls < 2
            },
            visit_n(2000),
        );
        assert_eq!(outcome.result.unwrap_err().name, ErrorName::Canceled);
        assert_eq!(i64::try_from(&outcome.extra["entries"]).unwrap(), 1024);
        // A failure keeps its name; the rest is not sent.
        let outcome = stream(
            &budget,
            &cancel,
            |_, _| true,
            |visit| {
                assert!(visit(b"a", WireEntry::unknown(b"a", 1)));
                Err(Status::new(ErrorName::NotFound, "gone"))
            },
        );
        assert_eq!(outcome.result.unwrap_err().name, ErrorName::NotFound);
        assert_eq!(i64::try_from(&outcome.extra["entries"]).unwrap(), 0);
        // Canceled: a walk that ends well still ends Canceled.
        cancel.store(true, Ordering::Release);
        let outcome = stream(&budget, &cancel, |_, _| true, |_| Ok(()));
        assert_eq!(outcome.result.unwrap_err().name, ErrorName::Canceled);
    }

    #[test]
    fn walk_batches_go_to_the_outbox() {
        let (ours, _peer) = UnixStream::pair().unwrap();
        let (outbox, mut rx) = outbox(SessionId(1), Arc::new(Link::new(ours)), 1000);
        let cancel = AtomicBool::new(false);
        assert!(outbox.flow().acquire(10, &cancel));
        let mut emit = walk_batches(&outbox, 4);
        let item = WireWalkItem { path: b"a".to_vec(), entry: WireEntry::unknown(b"a", 1) };
        assert!(emit(vec![item.clone()], 10));
        assert!(format!("{:?}", rx.try_recv().unwrap()).contains("WalkBatch"));
        drop(rx);
        assert!(outbox.flow().acquire(5, &cancel));
        assert!(!emit(vec![item], 5));
        assert_eq!(outbox.flow().in_flight(), 10);
    }
}
