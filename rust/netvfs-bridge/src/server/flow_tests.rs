// SPDX-License-Identifier: LGPL-2.1-or-later
// Restriction lints that only add noise to tests.
#![allow(clippy::assertions_on_result_states, clippy::arithmetic_side_effects)]

use super::{
    Arc, AtomicBool, Duration, FlowBudget, Link, MAX_QUEUED, Ordering, OutSignal, SessionId, UnixStream,
    mpsc, outbox, run_writer,
};
use crate::test_support::{pair, raw_pair, wire_entry};
use futures_lite::StreamExt as _;
use std::io::Read as _;
use std::thread;
use std::time::Instant;

const SID: SessionId = SessionId(3);

fn link() -> (Arc<Link>, UnixStream) {
    let (ours, peer) = UnixStream::pair().unwrap();
    (Arc::new(Link::new(ours)), peer)
}

fn small(n: u32) -> OutSignal {
    OutSignal::JobProgress { job: n, done: 0, total: -1 }
}

fn acquire_on_thread(
    budget: &Arc<FlowBudget>,
    bytes: usize,
    cancel: &Arc<AtomicBool>,
) -> mpsc::UnboundedReceiver<(bool, Instant)> {
    let (tx, rx) = mpsc::unbounded_channel();
    let (budget, cancel) = (Arc::clone(budget), Arc::clone(cancel));
    thread::spawn(move || {
        let got = budget.acquire(bytes, &cancel);
        tx.send((got, Instant::now())).unwrap();
    });
    rx
}

fn still_waiting(rx: &mut mpsc::UnboundedReceiver<(bool, Instant)>) -> bool {
    thread::sleep(Duration::from_millis(60));
    rx.try_recv().is_err()
}

fn result(rx: &mut mpsc::UnboundedReceiver<(bool, Instant)>) -> (bool, Instant) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(r) = rx.try_recv() {
            return r;
        }
        assert!(Instant::now() < deadline, "acquire did not return");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn budget_admits_up_to_the_limit() {
    let budget = FlowBudget::new(100);
    let cancel = AtomicBool::new(false);
    assert!(budget.acquire(60, &cancel));
    assert!(budget.acquire(40, &cancel));
    assert_eq!(budget.in_flight(), 100);
    assert!(budget.acquire(30, &cancel));
    assert_eq!(budget.in_flight(), 130);
    budget.release(0);
    assert_eq!(budget.in_flight(), 130);
    budget.release(30);
    assert_eq!(budget.in_flight(), 100);
    budget.release(500);
    assert_eq!(budget.in_flight(), 0);
    assert!(!budget.is_closed());
    assert!(budget.acquire(100, &cancel));
    assert!(budget.acquire(usize::MAX, &cancel));
    assert_eq!(budget.in_flight(), usize::MAX);
    budget.release(usize::MAX);
    assert_eq!(budget.in_flight(), 0);
}

#[test]
fn budget_blocks_until_release() {
    let budget = Arc::new(FlowBudget::new(10));
    let cancel = Arc::new(AtomicBool::new(false));
    assert!(budget.acquire(11, &cancel));
    let mut waiting = acquire_on_thread(&budget, 5, &cancel);
    assert!(still_waiting(&mut waiting));
    assert_eq!(budget.in_flight(), 11);
    budget.release(1);
    assert!(result(&mut waiting).0);
    assert_eq!(budget.in_flight(), 15);
}

#[test]
fn budget_cancel_and_close_unblock() {
    let budget = Arc::new(FlowBudget::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    assert!(budget.acquire(1, &cancel));
    let mut waiting = acquire_on_thread(&budget, 1, &cancel);
    assert!(still_waiting(&mut waiting));
    let canceled = Instant::now();
    cancel.store(true, Ordering::Release);
    let (got, at) = result(&mut waiting);
    assert!(!got);
    assert!(at.duration_since(canceled) < Duration::from_millis(500));
    assert_eq!(budget.in_flight(), 1);
    assert!(!budget.acquire(0, &cancel));

    let other = Arc::new(AtomicBool::new(false));
    let mut waiting = acquire_on_thread(&budget, 1, &other);
    assert!(still_waiting(&mut waiting));
    budget.close();
    assert!(!result(&mut waiting).0);
    assert!(budget.is_closed());
    assert!(!budget.acquire(0, &other));
    assert_eq!(budget.in_flight(), 1);
}

#[test]
fn outbox_queues_until_closed() {
    let (link, mut peer) = link();
    let (outbox, mut rx) = outbox(SID, Arc::clone(&link), 100);
    assert_eq!(outbox.session(), SID);
    assert!(format!("{outbox:?}").contains("closed: false"));
    assert!(outbox.signal(&small(1)));
    assert!(outbox.send_streamed(&small(2), 40));
    assert_eq!(*link.queued.borrow(), 2);
    let first = rx.try_recv().unwrap();
    assert_eq!((first.message.header().member().unwrap().as_str(), first.flow_bytes), ("JobProgress", 0));
    assert_eq!(rx.try_recv().unwrap().flow_bytes, 40);

    let cancel = AtomicBool::new(false);
    assert!(outbox.stream(&small(3), 7, &cancel));
    assert_eq!(outbox.flow().in_flight(), 7);
    assert_eq!(rx.try_recv().unwrap().flow_bytes, 7);

    assert!(!outbox.is_closed());
    outbox.close();
    assert!(outbox.is_closed());
    assert!(format!("{outbox:?}").contains("closed: true"));
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(peer.read(&mut buf).unwrap(), 0);
    outbox.close();
    assert!(outbox.is_closed());
    let queued = *link.queued.borrow();
    assert!(!outbox.signal(&small(4)));
    outbox.flow().release(7);
    assert!(outbox.flow().acquire(9, &cancel));
    assert!(!outbox.send_streamed(&small(5), 9));
    assert_eq!(outbox.flow().in_flight(), 0);
    assert_eq!(*link.queued.borrow(), queued);
    assert!(rx.try_recv().is_err());
}

#[test]
fn outbox_without_writer() {
    let (link, _peer) = link();
    let (outbox, rx) = outbox(SID, Arc::clone(&link), 100);
    drop(rx);
    let cancel = AtomicBool::new(false);
    assert!(!outbox.signal(&small(1)));
    assert!(!outbox.stream(&small(2), 30, &cancel));
    assert_eq!(outbox.flow().in_flight(), 0);
    assert_eq!(*link.queued.borrow(), 0);
    let (outbox, mut rx) = super::outbox(SID, link, 100);
    assert!(!outbox.stream(&small(3), 30, &AtomicBool::new(true)));
    assert_eq!(outbox.flow().in_flight(), 0);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn room_and_closed_waits() {
    let (link, _peer) = link();
    for _ in 0..MAX_QUEUED - 1 {
        link.queued_add();
    }
    tokio::time::timeout(Duration::from_secs(1), link.wait_for_room()).await.unwrap();
    link.queued_add();
    assert!(tokio::time::timeout(Duration::from_millis(50), link.wait_for_room()).await.is_err());
    let waiter = {
        let link = Arc::clone(&link);
        tokio::spawn(async move { link.wait_for_room().await })
    };
    tokio::task::yield_now().await;
    link.queued_sub();
    tokio::time::timeout(Duration::from_secs(1), waiter).await.unwrap().unwrap();
    for _ in 0..MAX_QUEUED + 5 {
        link.queued_sub();
    }
    assert_eq!(*link.queued.borrow(), 0);

    assert!(tokio::time::timeout(Duration::from_millis(20), link.wait_closed()).await.is_err());
    assert!(!link.is_closed());
    link.close();
    assert!(link.is_closed());
    tokio::time::timeout(Duration::from_secs(1), link.wait_closed()).await.unwrap();
}

#[tokio::test]
async fn writer_sends_in_order() {
    let pair = pair().await;
    let link = Arc::new(Link::new(pair.shutdown));
    let (outbox, rx) = outbox(SID, Arc::clone(&link), 1000);
    let conn = zbus::Connection::from(&pair.server);
    let mut incoming = zbus::MessageStream::from(&pair.client);
    let writer = tokio::spawn(run_writer(conn, rx, Arc::clone(&link), Arc::clone(outbox.flow())));
    let cancel = AtomicBool::new(false);
    for n in 0..20 {
        assert!(outbox.stream(&small(n), 10, &cancel));
    }
    for n in 0..20 {
        let msg =
            tokio::time::timeout(Duration::from_secs(5), incoming.next()).await.unwrap().unwrap().unwrap();
        let (job, _, _): (u32, i64, i64) = msg.body().deserialize().unwrap();
        assert_eq!(job, n);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while outbox.flow().in_flight() > 0 || *link.queued.borrow() > 0 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(!outbox.flow().is_closed());
    outbox.close();
    tokio::time::timeout(Duration::from_secs(1), writer).await.unwrap().unwrap();
    assert!(outbox.flow().is_closed());
    assert!(!outbox.signal(&small(99)));
}

#[tokio::test]
async fn writer_close_drains_the_queue() {
    let (server, shutdown, client) = raw_pair().await;
    let link = Arc::new(Link::new(shutdown));
    let (outbox, rx) = outbox(SID, Arc::clone(&link), usize::MAX);
    let conn = zbus::Connection::from(&server);
    let writer = tokio::spawn(run_writer(conn, rx, Arc::clone(&link), Arc::clone(outbox.flow())));
    let entries = vec![wire_entry(); 512];
    let batch = OutSignal::ListBatch { request: 1, entries };
    let cancel = AtomicBool::new(false);
    let mut sent = 0usize;
    while sent < 20 {
        assert!(outbox.stream(&batch, 1000, &cancel));
        sent += 1;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(outbox.flow().in_flight() > 0);
    assert!(*link.queued.borrow() > 0);
    outbox.close();
    tokio::time::timeout(Duration::from_secs(1), writer).await.unwrap().unwrap();
    assert_eq!(outbox.flow().in_flight(), 0);
    assert_eq!(*link.queued.borrow(), 0);
    assert!(outbox.flow().is_closed());
    drop(client);
}

#[tokio::test]
async fn writer_stops_on_a_failed_send() {
    let pair = pair().await;
    let link = Arc::new(Link::new(pair.shutdown));
    let (outbox, rx) = outbox(SID, Arc::clone(&link), usize::MAX);
    let conn = zbus::Connection::from(&pair.server);
    drop(pair.client);
    drop(pair.server);
    let writer = tokio::spawn(run_writer(conn, rx, Arc::clone(&link), Arc::clone(outbox.flow())));
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while outbox.stream(&small(1), 10, &cancel) {
        assert!(Instant::now() < deadline, "the writer kept going");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::timeout(Duration::from_secs(1), writer).await.unwrap().unwrap();
    assert!(link.is_closed());
    assert!(outbox.flow().is_closed());
    assert_eq!(outbox.flow().in_flight(), 0);
}
