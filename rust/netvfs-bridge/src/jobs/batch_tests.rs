// SPDX-License-Identifier: LGPL-2.1-or-later
// Restriction lints that only add noise to tests.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Batcher, ENTRY_FIXED_BYTES, FlowBudget, MAX_LIST_BATCH_BYTES, Ordering, Status, WireEntry, WireWalkItem,
    drain, entry_wire_size, list_batches, walk_item_wire_size,
};
use crate::server::SessionId;
use crate::server::flow::{Link, outbox};
use netvfs_bridge_proto::ErrorName;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn entry(name: &str) -> WireEntry {
    WireEntry::unknown(name.as_bytes(), 1)
}

#[allow(clippy::trivially_copy_pass_by_ref)] // the batcher's size function takes a reference
const fn sized(n: &usize) -> usize {
    *n
}

type Sent = Vec<(Vec<usize>, usize)>;

#[test]
fn wire_sizes_count_every_variable_field() {
    let mut e = entry("abc");
    assert_eq!(entry_wire_size(&e), ENTRY_FIXED_BYTES + 3);
    e.owner = "ow".into();
    e.group = "grp".into();
    e.content_type = "text/x".into();
    e.etag = b"12345".to_vec();
    assert_eq!(entry_wire_size(&e), ENTRY_FIXED_BYTES + 3 + 2 + 3 + 6 + 5);
    let item = WireWalkItem { path: b"dir/abc".to_vec(), entry: e };
    assert_eq!(walk_item_wire_size(&item), ENTRY_FIXED_BYTES + 19 + 7);
}

#[test]
fn batches_close_at_the_item_count() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sent: Sent = Vec::new();
    let mut b = Batcher::new(
        3,
        sized,
        |items, bytes| {
            sent.push((items, bytes));
            true
        },
        &budget,
        &cancel,
    );
    for n in 1..=7 {
        assert!(b.add(n));
    }
    assert!(format!("{b:?}").contains("items: 1"));
    assert!(b.flush());
    assert!(b.flush(), "nothing left is fine");
    drop(b);
    assert_eq!(sent, [(vec![1, 2, 3], 6), (vec![4, 5, 6], 15), (vec![7], 7)]);
    assert_eq!(budget.in_flight(), 28, "the emitter owns the bytes it got");
}

#[test]
fn batches_close_before_the_byte_limit() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sent: Sent = Vec::new();
    let half = MAX_LIST_BATCH_BYTES / 2;
    let mut b = Batcher::new(
        100,
        sized,
        |items, bytes| {
            sent.push((items, bytes));
            true
        },
        &budget,
        &cancel,
    );
    assert!(b.add(half));
    assert!(b.add(half));
    assert!(b.add(1));
    assert!(b.add(MAX_LIST_BATCH_BYTES + 1));
    assert!(b.add(2));
    assert!(b.flush());
    drop(b);
    assert_eq!(
        sent,
        [
            (vec![half, half], 2 * half),
            (vec![1], 1),
            (vec![MAX_LIST_BATCH_BYTES + 1], MAX_LIST_BATCH_BYTES + 1),
            (vec![2], 2)
        ]
    );
}

#[test]
fn zero_items_means_one() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sent = 0;
    let mut b = Batcher::new(
        0,
        sized,
        |items, _| {
            sent += items.len();
            true
        },
        &budget,
        &cancel,
    );
    assert!(b.add(1));
    assert!(b.add(1));
    drop(b);
    assert_eq!(sent, 2);
}

#[test]
fn cancel_and_failed_sends_stop() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut calls = 0;
    let mut b = Batcher::new(
        2,
        sized,
        |_, _| {
            calls += 1;
            false
        },
        &budget,
        &cancel,
    );
    assert!(b.add(1));
    assert!(!b.add(1), "a batch that could not go out stops");
    assert!(b.add(MAX_LIST_BATCH_BYTES));
    assert!(!b.add(1), "also when the byte limit closed it");
    cancel.store(true, Ordering::Release);
    assert!(!b.add(1), "canceled with room left");
    assert!(!b.flush());
    drop(b);
    assert_eq!(calls, 2);
}

#[test]
fn a_full_budget_waits_and_a_closed_one_stops() {
    let budget = FlowBudget::new(10);
    let cancel = AtomicBool::new(false);
    let mut sent = 0;
    let mut b = Batcher::new(
        1,
        sized,
        |_, bytes| {
            sent += bytes;
            true
        },
        &budget,
        &cancel,
    );
    assert!(b.add(11));
    budget.close();
    assert!(!b.add(1), "the session is gone");
    drop(b);
    assert_eq!(sent, 11);
    let budget = FlowBudget::new(10);
    assert!(budget.acquire(11, &cancel));
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        flag.store(true, Ordering::Release);
    });
    let mut b = Batcher::new(1, sized, |_, _| true, &budget, &cancel);
    assert!(!b.add(1));
    stopper.join().unwrap();
    assert_eq!(budget.in_flight(), 11);
}

#[test]
fn add_all_sends_each_backend_batch() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sent: Sent = Vec::new();
    let mut b = Batcher::new(
        2,
        sized,
        |items, bytes| {
            sent.push((items, bytes));
            true
        },
        &budget,
        &cancel,
    );
    assert!(b.add_all(&[1, 2, 3]));
    assert!(b.add_all(&[]));
    assert!(b.add_all(&[4]));
    drop(b);
    assert_eq!(sent, [(vec![1, 2], 3), (vec![3], 3), (vec![4], 4)]);
    let mut b = Batcher::new(2, sized, |_, _| false, &budget, &cancel);
    assert!(!b.add_all(&[1, 2, 3]));
    assert!(!b.add_all(&[1]), "the flush at the end fails");
}

#[test]
fn drain_flushes_the_rest_and_keeps_failures() {
    let budget = FlowBudget::new(usize::MAX);
    let cancel = AtomicBool::new(false);
    let mut sent = Vec::new();
    let mut b = Batcher::new(
        10,
        sized,
        |items, _| {
            sent.extend(items);
            true
        },
        &budget,
        &cancel,
    );
    assert!(
        drain(&mut b, |b| {
            assert!(b.add(5));
            Ok(())
        })
        .is_ok()
    );
    let failure = drain(&mut b, |b| {
        assert!(b.add(6));
        Err(Status::new(ErrorName::NotFound, "gone"))
    });
    assert_eq!(failure.unwrap_err().name, ErrorName::NotFound);
    drop(b);
    assert_eq!(sent, [5], "a failed producer's rest is not sent");
    let mut b = Batcher::new(10, sized, |_, _| false, &budget, &cancel);
    let unsent = drain(&mut b, |b| {
        assert!(b.add(1));
        Ok(())
    });
    assert_eq!(unsent.unwrap_err().name, ErrorName::Canceled);
}

#[test]
fn list_batches_go_to_the_outbox() {
    let (ours, _peer) = UnixStream::pair().unwrap();
    let (outbox, mut rx) = outbox(SessionId(1), Arc::new(Link::new(ours)), 1000);
    let cancel = AtomicBool::new(false);
    assert!(outbox.flow().acquire(40, &cancel));
    let mut emit = list_batches(&outbox, 7);
    assert!(emit(vec![entry("a")], 40));
    let queued = rx.try_recv().unwrap();
    assert!(format!("{queued:?}").contains("ListBatch"));
    assert_eq!(outbox.flow().in_flight(), 40, "the writer gives the bytes back");
    drop(rx);
    assert!(outbox.flow().acquire(5, &cancel));
    assert!(!emit(vec![entry("b")], 5));
    assert_eq!(outbox.flow().in_flight(), 40, "a failed send gives its bytes back");
}
