// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Arc, AtomicUsize, ErrorName, Handles, Instant, Lane, Ordering, Phase, StateTracker, THREAD_NAME, Turn,
    Work, Worker, drops_connection,
};
use crate::locations::mock::{Mock, MockHandle, Seen, blocking, recv, reporting, spec, status, task};
use crate::locations::state::StateSignal;
use std::sync::mpsc;
use std::time::Duration;

fn worker(mock: &Arc<Mock>) -> Worker<Mock> {
    Worker::start(Arc::clone(mock), spec("account:1", "h"), Lane::Bulk, Arc::default()).unwrap()
}

fn tracked(mock: &Arc<Mock>) -> (Worker<Mock>, Arc<StateTracker>, StateSignal) {
    let signal = StateSignal::default();
    let tracker = StateTracker::new(signal.clone());
    let w =
        Worker::start(Arc::clone(mock), spec("account:1", "h"), Lane::Bulk, Arc::clone(&tracker)).unwrap();
    (w, tracker, signal)
}

fn wait_phase(w: &Worker<Mock>, phase: Phase) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while w.phase() != phase {
        assert!(Instant::now() < deadline, "the worker stayed {:?}", w.phase());
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn wait_finished(w: &Worker<Mock>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !w.finished() {
        assert!(Instant::now() < deadline, "the worker did not finish");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn wait_idle(w: &Worker<Mock>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while w.idle_since().is_none() {
        assert!(Instant::now() < deadline, "the worker stayed busy");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn lazy_connection_in_order_and_reset_after_each_item() {
    let mock = Mock::new();
    let w = worker(&mock);
    assert_eq!(w.lane(), Lane::Bulk);
    assert!(w.idle_since().is_some());
    assert_eq!(mock.count("create"), 0);
    let (tx, rx) = mpsc::channel();
    for _ in 0..3 {
        w.post(task(), reporting(&tx, Ok(())));
    }
    assert_eq!([recv(&rx), recv(&rx), recv(&rx)], [Seen::Conn(1), Seen::Conn(1), Seen::Conn(1)]);
    wait_idle(&w);
    assert_eq!(mock.log(), ["create 1 account:1", "establish 1 s0", "reset 1", "reset 1", "reset 1"]);
    drop(w);
    assert_eq!(mock.log().last().map(String::as_str), Some("free 1"));
    assert_eq!(mock.live(), 0);
}

#[test]
fn which_results_drop_the_connection() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    w.post(task(), reporting(&tx, Err(status(ErrorName::NotFound))));
    assert_eq!(recv(&rx), Seen::Conn(1));
    let drops =
        [ErrorName::Canceled, ErrorName::ConnectionLost, ErrorName::Timeout, ErrorName::NetworkUnreachable];
    for (next, name) in (1..).zip(drops) {
        w.post(task(), reporting(&tx, Err(status(name))));
        assert_eq!(recv(&rx), Seen::Conn(next), "{name:?}");
        mock.wait_for("free", usize::try_from(next).unwrap());
    }
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(5));
    wait_idle(&w);
    assert_eq!(mock.count("create"), 5);
    assert_eq!(mock.count("reset 1"), 1);
    assert_eq!(mock.count("reset 5"), 1);
    assert_eq!(mock.live(), 1);
    assert!(drops_connection(&Err(status(ErrorName::Timeout))));
    assert!(!drops_connection(&Err(status(ErrorName::AuthFailed))));
    assert!(!drops_connection(&Ok(())));
}

#[test]
fn a_canceled_item_drops_the_connection_even_when_it_succeeds() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    let t = task();
    let flag = Arc::clone(&t.cancel);
    let work: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        flag.store(true, Ordering::Release);
        tx.send(turn.ready.map(|c| c.id).ok()).unwrap();
        Ok(())
    });
    w.post(t, work);
    assert_eq!(rx.recv().unwrap(), Some(1));
    mock.wait_for("free 1", 1);
    wait_idle(&w);
    assert_eq!(mock.count("reset"), 0);
}

#[test]
fn canceled_while_queued_never_connects() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    let t = task();
    t.cancel.store(true, Ordering::Release);
    w.post(t, reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    wait_idle(&w);
    assert_eq!(mock.count("create"), 0);
    let (htx, hrx) = mpsc::channel();
    let t = task();
    t.cancel.store(true, Ordering::Release);
    let work: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        htx.send((turn.handles.is_some(), turn.worker)).unwrap();
        Ok(())
    });
    w.post(t, work);
    assert_eq!(hrx.recv().unwrap(), (true, Some(w.id())));
}

#[test]
fn establish_and_create_failures_reach_the_item() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    mock.fail_establish(status(ErrorName::AuthFailed));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::AuthFailed));
    mock.wait_for("free 1", 1);
    mock.fail_create(status(ErrorName::Unsupported));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Unsupported));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    wait_idle(&w);
    assert_eq!(mock.count("create"), 2);
    assert_eq!(mock.count("reset"), 1);
}

#[test]
fn stop_cancels_the_running_item_and_drains_the_queue() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    let (_go, wait) = mpsc::channel();
    let running = task();
    let flag = Arc::clone(&running.cancel);
    w.post(running, blocking(&tx, wait, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    w.post(task(), reporting(&tx, Ok(())));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(w.load(), 3);
    assert!(w.idle_since().is_none());
    assert!(!w.finished());
    w.stop();
    assert!(flag.load(Ordering::Acquire));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    wait_finished(&w);
    assert_eq!(mock.count("cancel 1"), 1);
    assert_eq!(mock.count("free 1"), 1);
    assert_eq!(mock.count("create"), 1);
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(w.load(), 1);
    drop(w);
    assert_eq!(recv(&rx), Seen::Pending(ErrorName::Canceled));
}

#[test]
fn stop_while_establishing_cancels_the_connection() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    mock.hold_establish(true);
    w.post(task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 1", 1);
    w.stop();
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    wait_finished(&w);
    assert_eq!(mock.count("cancel 1"), 1);
    assert_eq!(mock.count("free 1"), 1);
}

#[test]
fn a_connection_created_for_a_canceled_request_is_canceled_at_once() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    mock.hold_create(true);
    let t = task();
    let flag = Arc::clone(&t.cancel);
    w.post(t, reporting(&tx, Ok(())));
    mock.wait_for("creating", 1);
    flag.store(true, Ordering::Release);
    mock.hold_create(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
    let log = mock.log();
    let cancel = log.iter().position(|l| l == "cancel 1").expect("canceled");
    let establish = log.iter().position(|l| l == "establish 1 s0").expect("established");
    assert!(cancel < establish, "{log:?}");
    wait_idle(&w);
    let mock = Mock::new();
    let w2 = worker(&mock);
    mock.hold_create(true);
    w2.post(task(), reporting(&tx, Ok(())));
    mock.wait_for("creating", 1);
    w2.stop();
    mock.hold_create(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
    wait_finished(&w2);
    let log = mock.log();
    let cancel = log.iter().position(|l| l == "cancel 1").expect("canceled");
    assert!(cancel < log.iter().position(|l| l.starts_with("establish 1")).unwrap(), "{log:?}");
    assert_eq!(mock.count("free 1"), 1);
}

#[test]
fn kick_cancels_only_a_canceled_running_item() {
    let mock = Mock::new();
    let w = worker(&mock);
    w.kick();
    let (tx, rx) = mpsc::channel();
    let (go, wait) = mpsc::channel();
    let running = task();
    let flag = Arc::clone(&running.cancel);
    w.post(running, blocking(&tx, wait, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(1));
    w.kick();
    assert_eq!(mock.count("cancel"), 0);
    flag.store(true, Ordering::Release);
    w.kick();
    mock.wait_for("cancel 1", 1);
    wait_idle(&w);
    assert_eq!(mock.count("free 1"), 1);
    drop(go);
    let (go, wait) = mpsc::channel();
    w.post(task(), blocking(&tx, wait, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    w.kick();
    go.send(()).unwrap();
    wait_idle(&w);
    assert_eq!(mock.count("cancel"), 1);
}

#[test]
fn handles_live_with_their_connection() {
    let mock = Mock::new();
    let w = worker(&mock);
    let (tx, rx) = mpsc::channel();
    let m = Arc::clone(&mock);
    let tx2 = tx.clone();
    let open: Work<Mock> = Box::new(move |turn: Turn<'_, Mock>| {
        let handles = turn.handles.unwrap();
        let a = handles.add(MockHandle::new(&m, "a"));
        let b = handles.add(MockHandle::new(&m, "b"));
        tx2.send(Seen::Conn(u64::from(a) * 10 + u64::from(b))).unwrap();
        Ok(())
    });
    w.post(task(), open);
    assert_eq!(recv(&rx), Seen::Conn(12));
    wait_idle(&w);
    assert_eq!(w.open_handles(), 2);
    let since = w.idle_since().unwrap();
    w.post(task(), reporting(&tx, Err(status(ErrorName::ConnectionLost))));
    assert_eq!(recv(&rx), Seen::Conn(1));
    mock.wait_for("free 1", 1);
    wait_idle(&w);
    assert!(w.idle_since().unwrap() >= since);
    assert_eq!(w.open_handles(), 0);
    let log = mock.log();
    let free = log.iter().position(|l| l == "free 1").unwrap();
    assert!(log.iter().position(|l| l == "close a").unwrap() < free);
    assert!(log.iter().position(|l| l == "close b").unwrap() < free);
}

#[test]
fn handles_table() {
    let count = Arc::new(AtomicUsize::new(9));
    let mut handles: Handles<&str> = Handles::new(Arc::clone(&count));
    assert_eq!(count.load(Ordering::Acquire), 0);
    assert!(handles.is_empty());
    assert_eq!(handles.add("a"), 1);
    assert_eq!(handles.add("b"), 2);
    assert_eq!((handles.len(), count.load(Ordering::Acquire)), (2, 2));
    assert_eq!(handles.get_mut(2).map(|h| *h), Some("b"));
    assert_eq!(handles.get_mut(3), None);
    assert_eq!(handles.remove(1), Some("a"));
    assert_eq!(handles.remove(1), None);
    assert_eq!(count.load(Ordering::Acquire), 1);
    assert!(!handles.is_empty());
    assert_eq!(handles.add("c"), 3);
    handles.clear();
    assert_eq!((handles.len(), count.load(Ordering::Acquire)), (0, 0));
    assert!(format!("{handles:?}").contains("next: 4"));
}

#[test]
fn ids_debug_and_failed_turns() {
    let mock = Mock::new();
    let (a, b) = (worker(&mock), worker(&mock));
    assert_ne!(a.id(), b.id());
    assert!(format!("{a:?}").contains("Bulk"));
    let turn: Turn<'_, Mock> = Turn::failed(status(ErrorName::Canceled));
    assert!(turn.handles.is_none() && turn.worker.is_none());
    assert!(format!("{turn:?}").contains("Err"));
    assert_eq!(THREAD_NAME, "nvb-w");
    let (tx, rx) = mpsc::channel();
    let named: Work<Mock> = Box::new(move |_turn: Turn<'_, Mock>| {
        tx.send(std::thread::current().name().map(str::to_owned)).unwrap();
        Ok(())
    });
    a.post(task(), named);
    assert_eq!(rx.recv().unwrap().as_deref(), Some("nvb-w"));
}

#[test]
fn the_phase_follows_the_connection_and_is_signalled() {
    let mock = Mock::new();
    let (w, tracker, signal) = tracked(&mock);
    assert_eq!(w.phase(), Phase::Closed);
    assert!(!signal.take());
    let (tx, rx) = mpsc::channel();
    mock.hold_establish(true);
    w.post(task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 1", 1);
    assert_eq!(w.phase(), Phase::Connecting);
    assert!(signal.take());
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Conn(1));
    assert_eq!(w.phase(), Phase::Established);
    assert!(signal.take());
    w.post(task(), reporting(&tx, Err(status(ErrorName::NotFound))));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!([recv(&rx), recv(&rx)], [Seen::Conn(1), Seen::Conn(1)]);
    wait_idle(&w);
    assert_eq!(w.phase(), Phase::Established);
    assert!(!signal.take(), "no change, no signal");
    w.post(task(), reporting(&tx, Err(status(ErrorName::ConnectionLost))));
    assert_eq!(recv(&rx), Seen::Conn(1));
    wait_phase(&w, Phase::Closed);
    assert_eq!(mock.count("free 1"), 1);
    assert!(signal.take());
    assert_eq!(tracker.failure(), None);
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    assert!(signal.take());
    w.stop();
    wait_finished(&w);
    assert_eq!(w.phase(), Phase::Closed);
    assert!(signal.take());
    assert_eq!(tracker.failure(), None);
}

#[test]
fn a_failed_attempt_is_recorded_until_one_succeeds() {
    let mock = Mock::new();
    let (w, tracker, signal) = tracked(&mock);
    let (tx, rx) = mpsc::channel();
    mock.fail_establish(status(ErrorName::AuthFailed));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::AuthFailed));
    assert_eq!((tracker.failure(), w.phase()), (Some(ErrorName::AuthFailed), Phase::Closed));
    assert!(signal.take());
    mock.fail_create(status(ErrorName::Unsupported));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Unsupported));
    assert_eq!((tracker.failure(), w.phase()), (Some(ErrorName::Unsupported), Phase::Closed));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Conn(2));
    assert_eq!((tracker.failure(), w.phase()), (None, Phase::Established));
    tracker.failed(ErrorName::Timeout);
    w.post(task(), reporting(&tx, Err(status(ErrorName::AuthFailed))));
    assert_eq!(recv(&rx), Seen::Conn(2));
    wait_idle(&w);
    assert_eq!(tracker.failure(), Some(ErrorName::Timeout));
}

#[test]
fn a_canceled_attempt_is_no_failure() {
    let mock = Mock::new();
    let (w, tracker, _signal) = tracked(&mock);
    tracker.failed(ErrorName::NetworkUnreachable);
    let (tx, rx) = mpsc::channel();
    mock.fail_establish(status(ErrorName::Canceled));
    w.post(task(), reporting(&tx, Ok(())));
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    assert_eq!(tracker.failure(), Some(ErrorName::NetworkUnreachable));
    mock.hold_establish(true);
    let t = task();
    let flag = Arc::clone(&t.cancel);
    w.post(t, reporting(&tx, Ok(())));
    mock.wait_for("establish 2", 1);
    flag.store(true, Ordering::Release);
    mock.queue_establish(Err(status(ErrorName::Timeout)));
    mock.hold_establish(false);
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Timeout));
    assert_eq!(tracker.failure(), Some(ErrorName::NetworkUnreachable));
    mock.hold_establish(true);
    w.post(task(), reporting(&tx, Ok(())));
    mock.wait_for("establish 3", 1);
    assert_eq!(w.phase(), Phase::Connecting);
    w.stop();
    assert_eq!(recv(&rx), Seen::Failed(ErrorName::Canceled));
    wait_finished(&w);
    assert_eq!((tracker.failure(), w.phase()), (Some(ErrorName::NetworkUnreachable), Phase::Closed));
}
