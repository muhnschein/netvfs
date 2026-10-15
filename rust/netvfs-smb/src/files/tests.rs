// SPDX-License-Identifier: LGPL-2.1-or-later
use std::time::Duration;

use super::*;
use crate::fake::{self, FT, Peer, Req, close_body, created_body, four, pair};
use crate::wire::Writer;

const T: Duration = Duration::from_secs(5);
const FID: FileId = [0x22; 16];
const MS: i64 = 1_609_459_200_000;

async fn started() -> (Conn, Peer) {
    let (client, peer) = pair().await;
    let conn = Conn::start(client, T);
    conn.set_limits(16 << 20, true);
    conn.grant(64);
    (conn, peer)
}

fn open_of(conn: &Conn) -> Open {
    Open { conn: conn.clone(), tree: Arc::new(Tree { id: 3, encrypt: false, share_type: 1 }), file_id: FID }
}

/// The byte at `offset` of the test file.
fn byte(offset: u64) -> u8 {
    offset.to_le_bytes()[0] ^ 0x5a
}

fn content(from: u64, to: u64) -> Vec<u8> {
    (from..to).map(byte).collect()
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

/// Offset and length of a READ.
fn read_of(req: &Req) -> (u64, usize) {
    assert_eq!(req.command(), Command::Read);
    let b = req.body();
    assert_eq!(&b[16..32], &FID);
    (le64(&b[8..16]), usize::try_from(le32(&b[4..8])).unwrap())
}

/// Offset and data of a WRITE.
fn write_of(req: &Req) -> (u64, Vec<u8>) {
    assert_eq!(req.command(), Command::Write);
    let b = req.body();
    assert_eq!(&b[16..32], &FID);
    let len = usize::try_from(le32(&b[4..8])).unwrap();
    (le64(&b[8..16]), b[48..][..len].to_vec())
}

fn read_body(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17).u8(80).u8(0).u32(u32::try_from(data.len()).unwrap()).u32(0).u32(0).bytes(data);
    w.into_vec()
}

fn write_body(count: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17).u16(0).u32(u32::try_from(count).unwrap()).u32(0).u16(0).u16(0);
    w.into_vec()
}

/// The next request that is not a CANCEL, and the CANCELs before it.
async fn next(peer: &mut Peer) -> (Req, usize) {
    let mut cancels = 0usize;
    loop {
        let req = peer.recv_one().await;
        if req.command() != Command::Cancel {
            return (req, cancels);
        }
        cancels = cancels.saturating_add(1);
    }
}

/// Answers a READ from a file of `size` bytes.
async fn answer_read(peer: &mut Peer, req: &Req, size: u64) {
    let (offset, count) = read_of(req);
    let msg = if offset >= size {
        fake::error(req, NtStatus::END_OF_FILE, 1)
    } else {
        let end = size.min(offset.saturating_add(u64::try_from(count).unwrap()));
        fake::response(req, NtStatus::SUCCESS, &read_body(&content(offset, end)), 1)
    };
    peer.send(&[msg], false).await;
}

/// Receives `n` READs, then answers them in order.
async fn serve_reads(peer: &mut Peer, size: u64, n: usize) -> Vec<(u64, usize)> {
    let mut reqs = Vec::new();
    while reqs.len() < n {
        reqs.push(next(peer).await.0);
    }
    for req in &reqs {
        answer_read(peer, req, size).await;
    }
    reqs.iter().map(read_of).collect()
}

async fn expect_close(peer: &mut Peer) -> Req {
    let (req, _) = next(peer).await;
    assert_eq!(req.command(), Command::Close);
    assert_eq!(&req.body()[8..24], &FID);
    req
}

async fn answer_close(peer: &mut Peer) {
    let req = expect_close(peer).await;
    peer.send(&[fake::response(&req, NtStatus::SUCCESS, &close_body(), 1)], false).await;
}

#[test]
fn chunk_is_the_server_maximum_within_limits() {
    assert_eq!(chunk(8 << 20, true), MAX_CHUNK);
    assert_eq!(chunk(8 << 20, false), crate::conn::CREDIT_UNIT);
    assert_eq!(chunk(1000, true), 1000);
    assert_eq!(chunk(MAX_CHUNK, true), MAX_CHUNK);
    assert_eq!(chunk(0, true), 1);
}

#[tokio::test]
async fn reads_are_pipelined_and_handed_out_in_order() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    assert_eq!(h.size(), Some(10_000));
    let mut buf = vec![0u8; 3000];
    let (r, seen) = tokio::join!(h.read(0, &mut buf, &c), serve_reads(&mut peer, 10_000, 3));
    assert_eq!(r, Ok(3000));
    assert_eq!(seen, [(0, 1000), (1000, 1000), (2000, 1000)]);
    assert_eq!(buf, content(0, 3000));
    // Where the last read ended: no new position.
    let mut buf = vec![0u8; 500];
    let (r, seen) = tokio::join!(h.read(3000, &mut buf, &c), serve_reads(&mut peer, 10_000, 1));
    assert_eq!(r, Ok(500));
    assert_eq!(seen, [(3000, 500)]);
    assert_eq!(buf, content(3000, 3500));
    // An empty buffer reads nothing.
    assert_eq!(h.read(0, &mut [], &c).await, Ok(0));
    let (r, ()) = tokio::join!(h.close(&c), answer_close(&mut peer));
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn read_ahead_requests_up_to_the_size_and_a_short_read_ends_the_file() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 2500, 1000);
    h.read_ahead(0, 1 << 30);
    let seen = serve_reads(&mut peer, 2500, 3).await;
    assert_eq!(seen, [(0, 1000), (1000, 1000), (2000, 500)]);
    // A read beyond what was asked ahead: past the size one READ, which
    // finds the end.
    let mut buf = vec![0u8; 4000];
    let (r, seen) = tokio::join!(h.read(0, &mut buf, &c), serve_reads(&mut peer, 2500, 1));
    assert_eq!(r, Ok(2500));
    assert_eq!(seen, [(2500, 1000)]);
    assert_eq!(&buf[..2500], content(0, 2500).as_slice());
    // At the end: 0.
    let (r, seen) = tokio::join!(h.read(2500, &mut buf, &c), serve_reads(&mut peer, 2500, 1));
    assert_eq!((r, seen), (Ok(0), vec![(2500, 1000)]));
    // A file that grew: read past the size one chunk at a time.
    let (r, seen) = tokio::join!(h.read(2500, &mut buf, &c), async {
        let mut seen = serve_reads(&mut peer, 4000, 1).await;
        seen.extend(serve_reads(&mut peer, 4000, 1).await);
        seen
    });
    assert_eq!(r, Ok(1500));
    assert_eq!(seen, [(2500, 1000), (3500, 1000)]);
    assert_eq!(&buf[..1500], content(2500, 4000).as_slice());
    // A hint of nothing, or at the size, sends nothing.
    h.read_ahead(0, 0);
    h.read_ahead(2500, 1000);
    drop(h);
    // The drop closes the file.
    expect_close(&mut peer).await;
}

#[tokio::test]
async fn reading_elsewhere_drops_what_was_asked_ahead() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    h.read_ahead(0, 3000);
    let mut ahead = Vec::new();
    for _ in 0..3 {
        ahead.push(next(&mut peer).await.0);
    }
    assert_eq!(ahead.iter().map(read_of).collect::<Vec<_>>(), [(0, 1000), (1000, 1000), (2000, 1000)]);
    let mut buf = vec![0u8; 100];
    let (r, mut peer) = tokio::join!(h.read(5000, &mut buf, &c), async {
        let (req, cancels) = next(&mut peer).await;
        // The READs asked ahead are canceled first, by their MessageId.
        assert_eq!(cancels, 3);
        answer_read(&mut peer, &req, 10_000).await;
        assert_eq!(read_of(&req), (5000, 100));
        // Their late answers are dropped.
        for a in &ahead {
            peer.send(&[fake::error(a, NtStatus::CANCELLED, 1)], false).await;
        }
        peer
    });
    assert_eq!(r, Ok(100));
    assert_eq!(buf, content(5000, 5100));
    // A hint behind the queue drops it as well.
    h.read_ahead(9000, 500);
    let (req, _) = next(&mut peer).await;
    assert_eq!(read_of(&req), (9000, 500));
    h.read_ahead(100, 100);
    let (req, cancels) = next(&mut peer).await;
    assert_eq!((read_of(&req), cancels), ((100, 100), 1));
    drop(h);
    expect_close(&mut peer).await;
}

#[tokio::test]
async fn at_most_the_window_is_on_the_way() {
    const N: usize = MAX_IN_FLIGHT / MAX_CHUNK;
    let (conn, mut peer) = started().await;
    conn.grant(512);
    let c = CancelToken::new();
    let size = u64::try_from((N + 2) * MAX_CHUNK).unwrap();
    let mut h = SmbRead::new(open_of(&conn), size, MAX_CHUNK);
    let mut buf = vec![0u8; (N + 2) * MAX_CHUNK];
    let (r, ()) = tokio::join!(h.read(0, &mut buf, &c), async {
        let mut reqs = Vec::new();
        for i in 0..N + 2 {
            // The window is full: the next READ waits for an answer.
            while reqs.len() < (N + i).min(N + 2) {
                reqs.push(next(&mut peer).await.0);
            }
            let quiet = tokio::time::timeout(Duration::from_millis(100), peer.frame()).await;
            assert!(quiet.is_err(), "a READ beyond the window");
            answer_read(&mut peer, &reqs[i], size).await;
        }
        let offsets: Vec<u64> = reqs.iter().map(|r| read_of(r).0).collect();
        let expected: Vec<u64> = (0..N + 2).map(|i| u64::try_from(i * MAX_CHUNK).unwrap()).collect();
        assert_eq!(offsets, expected);
    });
    assert_eq!(r, Ok((N + 2) * MAX_CHUNK));
    assert!(buf == content(0, size));
}

#[tokio::test]
async fn a_chunk_is_handed_out_in_pieces() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    h.read_ahead(0, 1000);
    assert_eq!(serve_reads(&mut peer, 10_000, 1).await, [(0, 1000)]);
    let mut buf = vec![0u8; 400];
    assert_eq!(h.read(0, &mut buf, &c).await, Ok(400));
    assert_eq!(buf, content(0, 400));
    let mut buf = vec![0u8; 600];
    assert_eq!(h.read(400, &mut buf, &c).await, Ok(600));
    assert_eq!(buf, content(400, 1000));
    // Both came from the one READ: the next request is the CLOSE.
    let (r, ()) = tokio::join!(h.close(&c), answer_close(&mut peer));
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn a_hint_of_nothing_or_where_the_queue_ends_keeps_the_queue() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    h.read_ahead(0, 1000);
    h.read_ahead(5000, 0);
    h.read_ahead(1000, 1000);
    let mut reqs = Vec::new();
    for _ in 0..2 {
        let (req, cancels) = next(&mut peer).await;
        assert_eq!(cancels, 0);
        reqs.push(req);
    }
    assert_eq!(reqs.iter().map(read_of).collect::<Vec<_>>(), [(0, 1000), (1000, 1000)]);
    for req in &reqs {
        answer_read(&mut peer, req, 10_000).await;
    }
    let mut buf = vec![0u8; 2000];
    assert_eq!(h.read(0, &mut buf, &c).await, Ok(2000));
    assert_eq!(buf, content(0, 2000));
    let (r, ()) = tokio::join!(h.close(&c), answer_close(&mut peer));
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn a_tripped_token_fails_the_read_even_with_data_queued() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    h.read_ahead(0, 1000);
    let seen = serve_reads(&mut peer, 10_000, 1).await;
    assert_eq!(seen, [(0, 1000)]);
    let tripped = CancelToken::new();
    tripped.cancel();
    let mut buf = vec![0u8; 10];
    let e = h.read(0, &mut buf, &tripped).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    // The handle still works: the queue went, the READ is made again.
    let (r, seen) = tokio::join!(h.read(0, &mut buf, &c), serve_reads(&mut peer, 10_000, 1));
    assert_eq!((r, seen), (Ok(10), vec![(0, 10)]));
    // A token tripped while waiting cancels the READ on the server.
    let late = CancelToken::new();
    let (r, ()) = tokio::join!(h.read(10, &mut buf, &late), async {
        let (req, _) = next(&mut peer).await;
        assert_eq!(read_of(&req), (10, 10));
        late.cancel();
        let cancel = peer.recv_one().await;
        assert_eq!(cancel.command(), Command::Cancel);
        assert_eq!(cancel.header.message_id, req.header.message_id);
    });
    assert_eq!(r.unwrap_err().name, ErrorName::Canceled);
}

#[tokio::test]
async fn read_failures() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    let mut buf = vec![0u8; 10];
    // A status.
    let (r, ()) = tokio::join!(h.read(0, &mut buf, &c), async {
        let (req, _) = next(&mut peer).await;
        peer.send(&[fake::error(&req, NtStatus::ACCESS_DENIED, 1)], false).await;
    });
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::PermissionDenied);
    assert!(e.message.starts_with("read"), "{e:?}");
    // More data than asked for.
    let (r, ()) = tokio::join!(h.read(0, &mut buf, &c), async {
        let (req, _) = next(&mut peer).await;
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &read_body(&[0; 11]), 1)], false).await;
    });
    assert_eq!(r.unwrap_err().name, ErrorName::ProtocolError);
    // Data outside the message.
    let (r, ()) = tokio::join!(h.read(0, &mut buf, &c), async {
        let (req, _) = next(&mut peer).await;
        let mut body = read_body(&[0; 10]);
        body.truncate(20);
        peer.send(&[fake::response(&req, NtStatus::SUCCESS, &body, 1)], false).await;
    });
    assert_eq!(r.unwrap_err().name, ErrorName::ProtocolError);
    // A failed CLOSE is reported.
    let (r, ()) = tokio::join!(h.close(&c), async {
        let req = expect_close(&mut peer).await;
        peer.send(&[fake::error(&req, NtStatus::FILE_CLOSED, 1)], false).await;
    });
    assert!(r.is_err());
    // A gone connection fails reads and hints quietly.
    let mut h = SmbRead::new(open_of(&conn), 10_000, 1000);
    drop(peer);
    let e = h.read(0, &mut buf, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
    h.read_ahead(0, 1000);
    assert_eq!(h.read(0, &mut [], &c).await.unwrap_err().name, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn a_canceled_close_still_closes() {
    let (conn, mut peer) = started().await;
    let h = SmbRead::new(open_of(&conn), 0, 1000);
    let tripped = CancelToken::new();
    tripped.cancel();
    let e = h.close(&tripped).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    expect_close(&mut peer).await;
}

#[tokio::test]
async fn writes_go_in_chunks_without_waiting_and_commit_flushes_and_closes() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, None, 1000);
    assert_eq!(h.position(), 0);
    let data = content(0, 2500);
    // Two full chunks go at once and nothing is waited for.
    h.write(&data, &c).await.unwrap();
    assert_eq!(h.position(), 2500);
    let mut writes = Vec::new();
    for _ in 0..2 {
        writes.push(next(&mut peer).await.0);
    }
    assert_eq!(
        writes.iter().map(write_of).collect::<Vec<_>>(),
        [(0, content(0, 1000)), (1000, content(1000, 2000))]
    );
    let (r, ()) = tokio::join!(h.commit(&c), async {
        let (last, _) = next(&mut peer).await;
        assert_eq!(write_of(&last), (2000, content(2000, 2500)));
        writes.push(last);
        for w in &writes {
            let n = write_of(w).1.len();
            peer.send(&[fake::response(w, NtStatus::SUCCESS, &write_body(n), 1)], false).await;
        }
        let (flush, _) = next(&mut peer).await;
        assert_eq!(flush.command(), Command::Flush);
        assert_eq!(&flush.body()[8..24], &FID);
        peer.send(&[fake::response(&flush, NtStatus::SUCCESS, &four(), 1)], false).await;
        answer_close(&mut peer).await;
    });
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn a_short_write_sends_the_rest_and_a_resumed_write_starts_at_its_position() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 500, None, 1000);
    assert_eq!(h.position(), 500);
    let data = content(500, 1500);
    h.write(&data, &c).await.unwrap();
    assert_eq!(h.position(), 1500);
    let (first, _) = next(&mut peer).await;
    assert_eq!(write_of(&first), (500, data.clone()));
    let (r, ()) = tokio::join!(h.commit(&c), async {
        peer.send(&[fake::response(&first, NtStatus::SUCCESS, &write_body(600), 1)], false).await;
        let (rest, _) = next(&mut peer).await;
        assert_eq!(write_of(&rest), (1100, content(1100, 1500)));
        peer.send(&[fake::response(&rest, NtStatus::SUCCESS, &write_body(400), 1)], false).await;
        let (flush, _) = next(&mut peer).await;
        peer.send(&[fake::response(&flush, NtStatus::SUCCESS, &four(), 1)], false).await;
        answer_close(&mut peer).await;
    });
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn a_write_of_nothing_fails_the_commit_and_closes() {
    for counts in [[0, 0], [300, 0]] {
        let (conn, mut peer) = started().await;
        let c = CancelToken::new();
        let mut h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, Some(MS), 1000);
        h.write(&content(0, 1000), &c).await.unwrap();
        let (first, _) = next(&mut peer).await;
        let (r, ()) = tokio::join!(h.commit(&c), async {
            peer.send(&[fake::response(&first, NtStatus::SUCCESS, &write_body(counts[0]), 1)], false).await;
            if counts[0] > 0 {
                let (rest, _) = next(&mut peer).await;
                assert_eq!(write_of(&rest).0, 300);
                peer.send(&[fake::response(&rest, NtStatus::SUCCESS, &write_body(counts[1]), 1)], false)
                    .await;
            }
            // No FLUSH and no times: the file is closed.
            expect_close(&mut peer).await;
        });
        let e = r.unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::ProtocolError, "write: the server accepted no data")
        );
    }
}

#[tokio::test]
async fn a_failed_write_fails_every_later_call() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, Some(MS), MAX_CHUNK);
    let data = vec![7u8; MAX_IN_FLIGHT];
    // The window holds four chunks; the fifth waits for the first.
    h.write(&data, &c).await.unwrap();
    let mut writes = Vec::new();
    for _ in 0..4 {
        writes.push(next(&mut peer).await.0);
    }
    let (r, mut peer) = tokio::join!(h.write(&data[..MAX_CHUNK], &c), async {
        peer.send(&[fake::error(&writes[0], NtStatus::DISK_FULL, 16)], false).await;
        // The other three are canceled.
        for w in &writes[1..] {
            let cancel = peer.recv_one().await;
            assert_eq!(cancel.command(), Command::Cancel);
            assert_eq!(cancel.header.message_id, w.header.message_id);
        }
        peer
    });
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::NoSpace);
    // Sticky: nothing more is sent, and commit only closes.
    assert_eq!(h.write(b"x", &c).await.unwrap_err(), e);
    assert_eq!(h.position(), u64::try_from(MAX_IN_FLIGHT).unwrap());
    let (r, ()) = tokio::join!(h.commit(&c), async {
        expect_close(&mut peer).await;
    });
    assert_eq!(r.unwrap_err(), e);
}

#[tokio::test]
async fn commit_sets_the_modification_time_after_the_close() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, Some(MS), 1000);
    let (r, ()) = tokio::join!(h.commit(&c), async {
        let (flush, _) = next(&mut peer).await;
        assert_eq!(flush.command(), Command::Flush);
        peer.send(&[fake::response(&flush, NtStatus::SUCCESS, &four(), 1)], false).await;
        answer_close(&mut peer).await;
        let reqs = peer.recv().await;
        let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
        assert_eq!(cmds, [Command::Create, Command::SetInfo, Command::Close]);
        let info = &reqs[1].body()[32..];
        assert_eq!(le64(&info[16..24]), FT);
        assert_eq!(le64(&info[8..16]), 0);
        let msgs = vec![
            fake::response(&reqs[0], NtStatus::SUCCESS, &created_body(0x20, 0, FID), 1),
            fake::response(&reqs[1], NtStatus::SUCCESS, &[2, 0], 1),
            fake::response(&reqs[2], NtStatus::SUCCESS, &close_body(), 1),
        ];
        peer.send(&fake::chain(msgs), false).await;
    });
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn abort_and_drop_close_without_flushing() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let mut h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, Some(MS), 1000);
    h.write(&content(0, 1500), &c).await.unwrap();
    let (first, _) = next(&mut peer).await;
    h.abort().await;
    // The WRITE on the way is canceled, the buffered rest never sent.
    let (close, cancels) = next(&mut peer).await;
    assert_eq!((close.command(), cancels), (Command::Close, 1));
    peer.send(&[fake::error(&first, NtStatus::CANCELLED, 1)], false).await;
    let h = SmbWrite::new(open_of(&conn), vec![u16::from(b'f')], 0, None, 1000);
    drop(h);
    expect_close(&mut peer).await;
}
