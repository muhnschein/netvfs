// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Arc, ConnectionState, Duration, ErrorName, HostRegistry, Instant, Lane, PoolSet, StateSignal, Turn, Work,
    WorkerId,
};
use crate::locations::mock::{Mock, MockHandle, Seen, blocking, recv, reporting, spec, status, task};
use std::sync::atomic::Ordering;
use std::sync::mpsc;

const IDLE: Duration = Duration::from_mins(1);

fn set(per_host: usize) -> (Arc<Mock>, PoolSet<Mock>) {
    let mock = Mock::new();
    (Arc::clone(&mock), PoolSet::new(mock, per_host))
}

fn signalled(per_host: usize) -> (Arc<Mock>, PoolSet<Mock>, StateSignal) {
    let (mock, set) = set(per_host);
    let signal = StateSignal::default();
    (mock, set.with_signal(signal.clone()), signal)
}

fn state(set: &PoolSet<Mock>, id: &str) -> ConnectionState {
    set.get(id).unwrap().state()
}

fn wait_state(set: &PoolSet<Mock>, id: &str, want: ConnectionState) {
    wait_until(|| state(set, id) == want);
}

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
    assert!(!hosts.try_acquire("c", 3));
    assert_eq!((hosts.in_use("c"), hosts.hosts_in_use()), (0, 2));
    hosts.release("a", 1);
    assert_eq!(hosts.in_use("a"), 1);
    assert!(hosts.try_acquire("a", 1));
    hosts.release("a", 5);
    assert_eq!((hosts.in_use("a"), hosts.hosts_in_use()), (0, 1));
    hosts.release("nobody", 1);
    assert_eq!(hosts.in_use("nobody"), 0);
    assert!(!hosts.try_acquire("b", usize::MAX));
    assert_eq!(hosts.in_use("b"), 2);
}

#[test]
fn lanes_and_their_limits() {
    let (mock, mut set) = set(4);
    assert!(set.add(spec("a", "h")));
    assert!(!set.add(spec("a", "other")));
    let (done_tx, done_rx) = mpsc::channel();
    set.submit("a", Lane::Interactive, task(), reporting(&done_tx, Ok(())));
    assert_eq!(recv(&done_rx), Seen::Conn(1));
    wait_until(|| pool_idle(&set, "a"));
    let (i1, seen) = busy(&mut set, "a", Lane::Interactive);
    assert_eq!(seen, Seen::Conn(1));
    set.submit("a", Lane::Interactive, task(), reporting(&done_tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 2)]);
    let (b1, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(2));
    let (b2, seen) = busy(&mut set, "a", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(3));
    set.submit("a", Lane::Interactive, task(), reporting(&done_tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 3), (Lane::Bulk, 1), (Lane::Bulk, 1)]);
    set.submit("a", Lane::Bulk, task(), reporting(&done_tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 3), (Lane::Bulk, 2), (Lane::Bulk, 1)]);
    set.submit("a", Lane::Bulk, task(), reporting(&done_tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 3), (Lane::Bulk, 2), (Lane::Bulk, 2)]);
    assert!(format!("{:?}", set.get("a").unwrap()).contains("connections: 3"));
    let (s1, seen) = busy(&mut set, "a", Lane::Stream);
    assert_eq!(seen, Seen::Conn(4));
    assert_eq!(set.hosts().in_use("fake://h:0"), 4);
    assert_eq!(set.get("a").unwrap().connection_count(), 4);
    assert!(!set.is_idle());
    for go in [i1, b1, b2, s1] {
        go.send(()).unwrap();
    }
    for _ in 0..4 {
        assert!(matches!(recv(&done_rx), Seen::Conn(_)));
    }
    wait_until(|| set.is_idle());
    assert_eq!(mock.count("create"), 4);
}

#[test]
fn a_full_host_borrows_another_lane_then_waits() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "H"));
    let (tx, rx) = mpsc::channel();
    let (go, seen) = busy(&mut set, "a", Lane::Interactive);
    assert_eq!(seen, Seen::Conn(1));
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(loads(&set, "a"), [(Lane::Interactive, 2)]);
    set.submit("b", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(set.get("b").unwrap().pending_count(), 1);
    assert!(!set.get("b").unwrap().is_idle());
    set.stop_all("a");
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
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
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    assert_eq!(state(&set, "b"), ConnectionState::Connected);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
    mock.wait_for("free 1", 1);
    wait_until(|| set.get("a").unwrap().retired.iter().all(|r| r.worker.finished()));
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!(set.closing(), 0);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
}

#[test]
fn an_evicted_connection_of_a_removed_pool_frees_no_slot_twice() {
    let (mock, mut set) = set(1);
    set.add(spec("a", "h"));
    set.add(spec("b", "h"));
    let (tx, rx) = mpsc::channel();
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    wait_until(|| pool_idle(&set, "a"));
    let (go, seen) = busy(&mut set, "b", Lane::Bulk);
    assert_eq!(seen, Seen::Conn(2));
    assert!(set.remove("a"));
    mock.wait_for("free 1", 1);
    wait_until(|| set.orphans.iter().all(|r| r.worker.finished()));
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!((set.closing(), set.hosts().in_use("fake://h:0")), (0, 1), "b still holds its slot");
    drop(go);
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
    assert!(!set.maintain(Instant::now() + IDLE * 2, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 1);
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
    assert!(!set.maintain((since + IDLE).checked_sub(Duration::from_millis(1)).unwrap(), IDLE));
    assert!(!set.maintain(since.checked_sub(Duration::from_secs(1)).unwrap(), IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 1);
    assert!(set.maintain(since + IDLE, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    let pending_free = set.hosts().in_use("fake://h:0") == 1;
    mock.wait_for("free 1", 1);
    wait_until(|| set.get("a").unwrap().retired.iter().all(|r| r.worker.finished()));
    assert_eq!(set.maintain(since + IDLE, IDLE), pending_free);
    assert_eq!(set.hosts().in_use("fake://h:0"), 0);
    assert!(!set.maintain(since + IDLE, IDLE));
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
    assert!(set.remove("b"));
    assert!(!set.remove("b"));
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::Canceled));
    set.retain(|s| s.id != "a");
    assert!(set.get("a").is_none());
    drop(go);
    assert_eq!(set.hosts().in_use("fake://h:0"), 1);
    wait_until(|| set.orphans.iter().all(|r| r.worker.finished()));
    assert_eq!(set.closing(), 1);
    assert!(set.maintain(Instant::now(), IDLE));
    assert_eq!((set.hosts().in_use("fake://h:0"), set.closing()), (0, 0));
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

#[test]
fn the_state_follows_the_live_connections() {
    let (mock, mut set, signal) = signalled(4);
    set.add(spec("a", "h"));
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    assert!(!signal.take());
    let (tx, rx) = mpsc::channel();
    mock.hold_establish(true);
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 1", 1);
    assert_eq!(state(&set, "a"), ConnectionState::Connecting);
    assert!(signal.take());
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
    assert_eq!(state(&set, "a"), ConnectionState::Connected);
    assert!(signal.take());
    mock.hold_establish(true);
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 2", 1);
    assert_eq!(state(&set, "a"), ConnectionState::Connected);
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Conn(2));
    wait_until(|| set.is_idle());
    let _before = signal.take();
    assert!(set.maintain(Instant::now() + IDLE, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    assert!(signal.take());
    mock.wait_for("free", 2);
    wait_until(|| set.get("a").unwrap().retired.iter().all(|r| r.worker.finished()));
    set.maintain(Instant::now(), IDLE);
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
}

#[test]
fn a_failed_attempt_shows_until_one_succeeds_or_a_disconnect() {
    let (mock, mut set, signal) = signalled(4);
    set.add(spec("a", "h"));
    let (tx, rx) = mpsc::channel();
    mock.fail_establish(status(ErrorName::NetworkUnreachable));
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::NetworkUnreachable));
    assert_eq!(state(&set, "a"), ConnectionState::Failed(ErrorName::NetworkUnreachable));
    assert!(signal.take());
    wait_until(|| set.is_idle());
    assert!(set.maintain(Instant::now() + IDLE, IDLE));
    assert_eq!(set.get("a").unwrap().connection_count(), 0);
    assert_eq!(state(&set, "a"), ConnectionState::Failed(ErrorName::NetworkUnreachable));
    mock.fail_establish(status(ErrorName::AuthFailed));
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::AuthFailed));
    assert_eq!(state(&set, "a"), ConnectionState::Failed(ErrorName::AuthFailed));
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(3));
    assert_eq!(state(&set, "a"), ConnectionState::Connected);
    mock.fail_establish(status(ErrorName::Timeout));
    set.submit("a", Lane::Bulk, task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Timeout));
    assert_eq!(state(&set, "a"), ConnectionState::Connected);
    set.submit("a", Lane::Interactive, task(), reporting(&tx, Err(status(ErrorName::ConnectionLost))));
    assert_eq!(recv(&rx), Seen::Conn(3));
    wait_state(&set, "a", ConnectionState::Failed(ErrorName::Timeout));
    let _before = signal.take();
    set.stop_all("a");
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    assert!(signal.take());
}

#[test]
fn a_connection_being_closed_is_not_counted() {
    let (mock, mut set, signal) = signalled(4);
    set.add(spec("a", "h"));
    set.add(spec("b", "i"));
    let (go, wait) = mpsc::channel::<()>();
    let (tx, rx) = mpsc::channel();
    let work: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        tx.send(turn.ready.as_ref().map(|c| c.id).ok()).unwrap();
        let _gone = wait.recv();
        Ok(())
    });
    set.submit("a", Lane::Bulk, task(), work);
    assert_eq!(rx.recv().unwrap(), Some(1));
    assert_eq!(state(&set, "a"), ConnectionState::Connected);
    let _before = signal.take();
    set.stop_all("a");
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    assert!(signal.take());
    assert!(!set.get("a").unwrap().retired[0].worker.finished());
    assert_eq!(state(&set, "b"), ConnectionState::Disconnected);
    drop(go);
    mock.wait_for("free 1", 1);
    assert_eq!(state(&set, "a"), ConnectionState::Disconnected);
    mock.hold_establish(true);
    let (tx, rx) = mpsc::channel();
    set.submit("b", Lane::Interactive, task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 2", 1);
    assert_eq!(state(&set, "b"), ConnectionState::Connecting);
    set.stop_all("b");
    assert_eq!(state(&set, "b"), ConnectionState::Disconnected);
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    mock.hold_establish(false);
    assert_eq!(state(&set, "b"), ConnectionState::Disconnected);
}
