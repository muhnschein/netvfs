// SPDX-License-Identifier: LGPL-2.1-or-later
// Pools, lanes and the per-host limit (port of pool.cpp, XB-12) over the
// fake backend.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::*;
use crate::locations::mock::{Mock, MockHandle, Seen, blocking, recv, reporting, spec, task};
use std::sync::atomic::Ordering;
use std::sync::mpsc;

const IDLE: Duration = Duration::from_mins(1);

fn set(per_host: usize) -> (Arc<Mock>, PoolSet<Mock>) {
    let mock = Mock::new();
    (Arc::clone(&mock), PoolSet::new(mock, per_host))
}

/// A busy connection: the item runs until `go` gets a message or drops.
fn busy(set: &mut PoolSet<Mock>, id: &str, lane: Lane) -> (mpsc::Sender<()>, Seen) {
    let (go, wait) = mpsc::channel();
    let (seen_tx, seen_rx) = mpsc::channel();
    set.submit(id, lane, task(), blocking(&seen_tx, wait, Ok(())));
    (go, recv(&seen_rx))
}

fn wait_until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn pool_idle(set: &PoolSet<Mock>, id: &str) -> bool {
    set.get(id).unwrap().is_idle()
}

fn loads(set: &PoolSet<Mock>, id: &str) -> Vec<(Lane, usize)> {
    set.get(id).unwrap().workers.iter().map(|w| (w.lane(), w.load())).collect()
}

#[test]
fn host_registry_counts() {
    let mut hosts = HostRegistry::new(2);
    assert_eq!(hosts.per_host(), 2);
    assert_eq!(HostRegistry::default().per_host(), 4);
    assert!(hosts.try_acquire("a", 1));
    assert!(hosts.try_acquire("a", 1));
    assert!(!hosts.try_acquire("a", 1));
    assert_eq!(hosts.in_use("a"), 2);
    assert!(hosts.try_acquire("b", 2));
    assert!(!hosts.try_acquire("c", 3)); // more than the limit at once
    assert_eq!((hosts.in_use("c"), hosts.hosts_in_use()), (0, 2));
    hosts.release("a", 1);
    assert_eq!(hosts.in_use("a"), 1);
    assert!(hosts.try_acquire("a", 1));
    hosts.release("a", 5); // never below zero
    assert_eq!((hosts.in_use("a"), hosts.hosts_in_use()), (0, 1));
    hosts.release("nobody", 1);
    assert_eq!(hosts.in_use("nobody"), 0);
    assert!(!hosts.try_acquire("b", usize::MAX)); // no overflow
    assert_eq!(hosts.in_use("b"), 2);
}

#[test]
fn lanes_and_their_limits() {
    let (mock, mut set) = set(4);
    assert!(set.add(spec("a", "h")));
    assert!(!set.add(spec("a", "other")));
    // An idle connection of the lane is used again.
    let (done_tx, done_rx) = mpsc::channel();
    set.submit("a", Lane::Interactive, task(), reporting(&done_tx, Ok(())));
    assert_eq!(recv(&done_rx), Seen::Conn(1));
    wait_until(|| pool_idle(&set, "a"));
    let (i1, seen) = busy(&mut set, "a", Lane::Interactive);
    assert_eq!(seen, Seen::Conn(1));
    // Interactive has one connection: the next item queues behind.
    set.submit("a", Lane::Interactive, task(), reporting(&done_tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 2)]);
    // Bulk has two.
    let (b1, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(2));
    let (b2, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(3));
    set.submit("a", Lane::Bulk, task(), reporting(&done_tx, Ok(())));
    set.submit("a", Lane::Bulk, task(), reporting(&done_tx, Ok(())));
    // The least loaded bulk connection got each.
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 2), (Lane::Bulk, 2), (Lane::Bulk, 2)]);
    // Stream has one, and with it the host is full.
    let (s1, seen) = busy(&mut set, "a", Lane::Stream);
    assert_eq!(seen, Seen::Conn(4));
    assert_eq!(set.hosts().in_use("fake://h:0"), 4);
    assert_eq!(set.get("a").unwrap().connection_count(), 4);
    assert!(!set.is_idle());
    for go in [i1, b1, b2, s1] {
        go.send(()).unwrap();
    }
    for _ in 0..3 {
        assert!(matches!(recv(&done_rx), Seen::Conn(_)));
    }
    wait_until(|| set.is_idle());
    assert_eq!(mock.count("create"), 4);
}

#[test]
fn a_full_host_borrows_another_lane_then_waits() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "H")); // the same host: host keys are lower case
    let (tx, rx) = mpsc::channel();
    let (go, seen) = busy(&mut set, "a", Lane::Interactive);
    assert_eq!(seen, Seen::Conn(1));
    // No bulk connection and no room: the interactive one is borrowed.
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 2)]);
    // Location b has no connection at all, and the busy one cannot be
    // closed: its work waits.
    set.submit("b", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(set.get("b").unwrap().pending_count(), 1);
    assert!(!set.get("b").unwrap().is_idle());
    // Disconnect a: once its connection has finished, b's work runs.
    set.stop_all("a");
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled)); // the borrowed item
    drop(go);
    wait_until(|| set.closing() == 1 && set.get("a").unwrap().retired[0].worker.finished());
    assert_eq!(set.hosts().in_use("fake://h:0"), 1); // counted until reaped
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!(recv(&rx), Seen::Conn(2));
    assert_eq!(set.get("b").unwrap().pending_count(), 0);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
    assert_eq!(mock.count("create"), 2);
}

#[test]
fn an_idle_connection_of_another_location_makes_room() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let (tx, rx) = mpsc::channel();
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    wait_until(|| pool_idle(&set, "a"));
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    // a's connection was closed, its slot counted free at once.
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
    mock.wait_for("free 1", 1);
    wait_until(|| set.get("a").unwrap().retired.iter().all(|r| r.worker.finished()));
    // Reaping it gives nothing back a second time.
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!(set.closing(), 0);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
}

#[test]
fn connections_with_handles_or_work_are_not_evicted() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let m = Arc::clone(&mock);
    let (tx, rx) = mpsc::channel();
    let open: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        turn.handles.unwrap().add(MockHandle::new(&m, "x"));
        tx.send(()).unwrap();
        Ok(())
    });
    set.submit("a", Lane::Stream, task(), open);
    rx.recv().unwrap();
    wait_until(|| pool_idle(&set, "a"));
    let (rtx, rrx) = mpsc::channel();
    set.submit("b", Lane::Stream, task(), reporting(&rtx, Ok(())));
    assert_eq!(set.get("b").unwrap().pending_count(), 1);
    assert_eq!(set.get("a").unwrap().connection_count(), 1);
    // An expired connection with a handle stays too.
    assert!(!set.maintain(Instant::now() + IDLE * 2, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 1);
    // Canceled while waiting: it ends with kick, on the core.
    set.get("b").unwrap().pending[0].task.cancel.store(true, Ordering::Release);
    set.kick();
    assert_eq!(recv(&rrx), Seen::Pending(ErrorName::Canceled));
    assert_eq!(set.get("b").unwrap().pending_count(), 0);
}

#[test]
fn kick_cancels_running_work_and_keeps_live_pending_work() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let (tx, rx) = mpsc::channel();
    let (go, wait) = mpsc::channel::<()>();
    let t = task();
    let flag = Arc::clone(&t.cancel);
    set.submit("a", Lane::Bulk, t, blocking(&tx, wait, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    set.kick();
    assert_eq!(mock.count("cancel"), 0);
    assert_eq!(set.get("b").unwrap().pending_count(), 1);
    flag.store(true, Ordering::Release);
    set.kick();
    mock.wait_for("cancel 1", 1);
    wait_until(|| pool_idle(&set, "a"));
    drop(go);
    // The canceled item dropped its connection; b still waits for a slot.
    assert_eq!(set.get("b").unwrap().pending_count(), 1);
}

#[test]
fn maintain_closes_idle_connections() {
    let (mock, mut set) = set(4);
    set.add(spec("a", "h"));
    let (tx, rx) = mpsc::channel();
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    wait_until(|| set.is_idle());
    let since = set.get("a").unwrap().workers[0].idle_since().unwrap();
    // Not yet: idle for less than the limit, or a clock behind.
    assert!(!set.maintain((since + IDLE).checked_sub(Duration::from_millis(1)).unwrap(), IDLE));
    assert!(!set.maintain(since.checked_sub(Duration::from_secs(1)).unwrap(), IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 1);
    // Exactly the limit.
    assert!(set.maintain(since + IDLE, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    // The slot counts until the thread has finished, which may already
    // be the case when maintain looks for finished ones.
    let pending_free = set.hosts().in_use("fake://h:0") == 1;
    mock.wait_for("free 1", 1);
    wait_until(|| set.get("a").unwrap().retired.iter().all(|r| r.worker.finished()));
    assert_eq!(set.maintain(since + IDLE, IDLE), pending_free);
    assert_eq!(set.hosts().in_use("fake://h:0"), 0);
    assert!(!set.maintain(since + IDLE, IDLE));
    // A busy connection is never idle.
    let (go, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(2));
    assert!(!set.maintain(Instant::now() + IDLE * 10, IDLE));
    drop(go);
}

#[test]
fn removing_a_pool_ends_its_work_and_keeps_slots_until_finished() {
    let (_mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let (tx, rx) = mpsc::channel();
    let (go, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(1));
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    // b goes: its waiting work ends.
    assert!(set.remove("b"));
    assert!(!set.remove("b"));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::Canceled));
    // a goes: its connection stops; the slot counts until it has finished.
    set.retain(|s| s.id != "a");
    assert!(set.get("a").is_none());
    drop(go);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
    wait_until(|| set.orphans.iter().all(|r| r.worker.finished()));
    assert_eq!(set.closing(), 1);
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!((set.hosts().in_use("fake://h:0"), set.closing()), (0, 0));
    // A new pool on the host gets the slot.
    set.add(spec("c", "h"));
    set.submit("c", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
}

#[test]
fn finished_orphans_free_their_slots_for_waiting_work() {
    let (_mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let (tx, rx) = mpsc::channel();
    let (go, _) = busy(&mut set, "a", Lane::Bulk);
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    set.remove("a");
    drop(go);
    wait_until(|| set.orphans.iter().all(|r| r.worker.finished()));
    // The next submit reaps the orphan and the waiting work runs first.
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    assert_eq!(recv(&rx), Seen::Conn(2));
    assert_eq!(set.closing(), 0);
}

#[test]
fn clear_removes_everything() {
    let (mock, mut set) = set(4);
    set.add(spec("a", "h"));
    set.add(spec("b", "i"));
    let (tx, rx) = mpsc::channel();
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    set.submit("b", Lane::Bulk, task(), reporting(&tx, Ok(())));
    recv(&rx);
    recv(&rx);
    set.clear();
    assert_eq!(set.iter().count(), 0);
    mock.wait_for("free", 2);
    wait_until(|| set.orphans.iter().all(|r| r.worker.finished()));
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!(set.hosts().hosts_in_use(), 0);
}

#[test]
fn unknown_locations_and_workers() {
    let (_mock, mut set) = set(4);
    let (tx, rx) = mpsc::channel();
    set.submit("nope", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::NotFound));
    set.add(spec("a", "h"));
    let (htx, hrx) = mpsc::channel();
    let probe: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        htx.send(turn.worker).unwrap();
        Ok(())
    });
    set.submit("a", Lane::Stream, task(), probe);
    let worker = hrx.recv().unwrap().unwrap();
    assert!(set.owns("a", worker));
    assert!(!set.owns("b", worker));
    assert!(!set.owns("a", WorkerId(u64::MAX)));
    set.submit_to("a", worker, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    set.submit_to("a", WorkerId(u64::MAX), task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::ConnectionLost));
    set.stop_all("a");
    assert!(!set.owns("a", worker));
    set.stop_all("nope");
    set.submit_to("a", worker, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::ConnectionLost));
    assert_eq!(set.backend().count("create"), 1);
    assert!(format!("{set:?}").contains("PoolSet"));
}

#[test]
fn copy_jobs_take_host_slots_too() {
    let (_mock, mut set) = set(1);
    set.add(spec("a", "h"));
    assert!(set.try_acquire_host("fake://h:0"));
    assert!(!set.try_acquire_host("fake://h:0"));
    let (tx, rx) = mpsc::channel();
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(set.get("a").unwrap().pending_count(), 1);
    set.release_host("fake://h:0");
    assert_eq!(recv(&rx), Seen::Conn(1));
}
