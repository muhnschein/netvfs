// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects, reason = "tests")]

use super::*;
use crate::fake::{Action, Fake, Rule};
use crate::proto::{
    FX_FAILURE, FX_NO_SUCH_FILE, FXF_CREAT, FXF_READ, FXF_WRITE, FXP_ATTRS, FXP_DATA, FXP_HANDLE, FXP_NAME, FXP_STATUS,
    StatusReply,
};
use tokio::io::DuplexStream;

const LONG: Duration = Duration::from_secs(10);

fn split(stream: DuplexStream) -> (tokio::io::ReadHalf<DuplexStream>, tokio::io::WriteHalf<DuplexStream>) {
    tokio::io::split(stream)
}

async fn start_with(fake: &Fake, timeout: Duration) -> (Client, ServerVersion, oneshot::Receiver<()>) {
    let (stream, _task) = fake.connect();
    let (r, w) = split(stream);
    let (ended_tx, ended_rx) = oneshot::channel();
    let on_end = async move {
        ended_tx.send(()).unwrap_or_default();
    };
    let (client, version) = Client::start(r, w, on_end, timeout, &CancelToken::new()).await.unwrap();
    (client, version, ended_rx)
}

async fn start(fake: &Fake) -> Client {
    start_with(fake, LONG).await.0
}

fn name(f: &Failure) -> ErrorName {
    f.status("x").name
}

/// Waits until `check` holds (the reader task runs on its own).
async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("condition not reached");
}

fn raw(kind: u8, id: u32, rest: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(rest.len() + 5).unwrap().to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(rest);
    out
}

#[tokio::test]
async fn handshake_reads_the_extensions() {
    let fake = Fake::new().with_extensions(&[("posix-rename@openssh.com", "1"), ("x@y", "2")]);
    let (_client, version, _) = start_with(&fake, LONG).await;
    assert_eq!(version.version, 3);
    assert!(version.offers("posix-rename@openssh.com", "1"));
    assert!(version.offers("x@y", "2"));
    assert_eq!(version.extensions.len(), 2);
}

#[tokio::test]
async fn handshake_refuses_other_versions() {
    let fake = Fake::new();
    fake.state().version = 4;
    let (stream, _task) = fake.connect();
    let (r, w) = split(stream);
    let (tx, rx) = oneshot::channel();
    let e = Client::start(r, w, async move { tx.send(()).unwrap_or_default() }, LONG, &CancelToken::new()).await.unwrap_err();
    assert_eq!((e.name, e.detail.as_str()), (ErrorName::Unsupported, "version 4"));
    // The channel is closed after a failed start.
    tokio::time::timeout(LONG, rx).await.unwrap().unwrap();
}

#[tokio::test]
async fn handshake_ends_on_timeout_and_cancel() {
    // Nothing answers on the other end.
    let (stream, _quiet) = tokio::io::duplex(1024);
    let (r, w) = split(stream);
    let e = Client::start(r, w, async {}, Duration::from_millis(50), &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Timeout);

    let (stream, _quiet) = tokio::io::duplex(1024);
    let (r, w) = split(stream);
    let cancel = CancelToken::new();
    let trip = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        trip.cancel();
    });
    let e = Client::start(r, w, async {}, LONG, &cancel).await.unwrap_err();
    assert_eq!(e, Status::canceled());
}

#[tokio::test]
async fn handshake_refuses_a_broken_version_and_a_closed_channel() {
    let (stream, mut server) = tokio::io::duplex(1024);
    let (r, w) = split(stream);
    tokio::spawn(async move {
        let mut init = [0; 9];
        server.read_exact(&mut init).await.unwrap();
        assert_eq!(init, [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        // VERSION with a truncated extension.
        server.write_all(&[0, 0, 0, 7, 2, 0, 0, 0, 3, 0, 0]).await.unwrap();
        tokio::time::sleep(LONG).await;
    });
    let e = Client::start(r, w, async {}, LONG, &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError);

    let (stream, server) = tokio::io::duplex(1024);
    drop(server);
    let (r, w) = split(stream);
    let e = Client::start(r, w, async {}, LONG, &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn pipelined_replies_find_their_requests() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"0123456789");
    // The first read is answered last.
    fake.rule(Rule::new(FXP_READ, Action::Delay(Duration::from_millis(50))).once());
    let client = start(&fake).await;
    let c = CancelToken::new();
    let h = client.open(b"/home/u/a", FXF_READ, &Attrs::default(), &c).await.unwrap();
    let first = client.read(&h, 0, 2).unwrap();
    let second = client.read(&h, 4, 3).unwrap();
    let third = client.read(&h, 9, 5).unwrap();
    assert_eq!(third.wait(&c).await, Ok(Reply::Data(b"9".to_vec())));
    assert_eq!(second.wait(&c).await, Ok(Reply::Data(b"456".to_vec())));
    assert_eq!(first.wait(&c).await, Ok(Reply::Data(b"01".to_vec())));
    let eof = client.read(&h, 10, 5).unwrap().wait(&c).await.unwrap();
    assert!(matches!(eof, Reply::Status(StatusReply { code: FX_EOF, .. })));
    client.close(&h, &c).await.unwrap();
    assert_eq!(fake.open_handles(), 0);
    // Ids are unique and increase.
    let ids: Vec<u32> = fake.state().log.iter().map(|l| l.id).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
}

#[tokio::test]
async fn typed_requests_and_their_replies() {
    let fake = Fake::new();
    fake.file("/home/u/f", b"abc");
    fake.link("/home/u/l", "f");
    let client = start(&fake).await;
    let c = CancelToken::new();
    assert_eq!(client.stat(b"/home/u/l", true, &c).await.unwrap().size, Some(3));
    assert_eq!(client.stat(b"/home/u/l", false, &c).await.unwrap().permissions, Some(0o120_777));
    let missing = client.stat(b"/home/u/nope", true, &c).await.unwrap_err();
    assert_eq!(missing.code(), Some(FX_NO_SUCH_FILE));
    assert_eq!(client.path_of(PathOf::Realpath(b"."), &c).await.unwrap(), b"/home/u");
    assert_eq!(client.path_of(PathOf::Readlink(b"/home/u/l"), &c).await.unwrap(), b"f");
    client.simple(Simple::Mkdir(b"/home/u/d", Attrs { permissions: Some(0o700), ..Attrs::default() }), &c).await.unwrap();
    assert_eq!(fake.node("/home/u/d"), Some(crate::fake::Node::Dir { mode: 0o700, mtime: 7000 }));
    client.simple(Simple::Rename(b"/home/u/d", b"/home/u/e"), &c).await.unwrap();
    client.simple(Simple::Rmdir(b"/home/u/e"), &c).await.unwrap();
    client.simple(Simple::Symlink { target: b"f", link: b"/home/u/s" }, &c).await.unwrap();
    let symlink = fake.requests(FXP_SYMLINK);
    assert_eq!(symlink[0].strings, [b"f".to_vec(), b"/home/u/s".to_vec()]);
    client.simple(Simple::Setstat(b"/home/u/f", Attrs { size: Some(1), ..Attrs::default() }), &c).await.unwrap();
    assert_eq!(fake.data("/home/u/f").unwrap(), b"a");
    client.simple(Simple::Remove(b"/home/u/f"), &c).await.unwrap();
    let failed = client.simple(Simple::Remove(b"/home/u/f"), &c).await.unwrap_err();
    assert_eq!(failed.code(), Some(FX_NO_SUCH_FILE));
    // A folder listing ends with None.
    let d = client.opendir(b"/home/u", &c).await.unwrap();
    let names = client.readdir(&d, &c).await.unwrap().unwrap();
    assert!(names.iter().any(|n| n.filename == b"l"));
    assert_eq!(client.readdir(&d, &c).await.unwrap(), None);
    client.close(&d, &c).await.unwrap();
    assert_eq!(client.close(&d, &c).await.unwrap_err().code(), Some(FX_FAILURE));
    let w = client.open(b"/home/u/w", FXF_WRITE | FXF_CREAT, &Attrs::default(), &c).await.unwrap();
    assert_eq!(client.write(&w, 2, b"xy").unwrap().wait(&c).await.map(ok), Ok(Ok(())));
    assert_eq!(client.fstat(&w, &c).await.unwrap().size, Some(4));
    let reply = client.extended("fsync@openssh.com", &[Field::Str(&w)], &c).await.unwrap();
    assert_eq!(ok(reply), Ok(()));
    let unknown = client.extended("nope@x", &[Field::U64(1)], &c).await.unwrap();
    assert_eq!(ok(unknown).unwrap_err().code(), Some(crate::proto::FX_OP_UNSUPPORTED));
    assert_eq!(fake.requests(FXP_EXTENDED)[1].ext, "nope@x");
}

#[tokio::test]
async fn replies_of_the_wrong_kind_are_protocol_errors() {
    let fake = Fake::new();
    let client = start(&fake).await;
    let c = CancelToken::new();
    // STAT answered by a HANDLE, REALPATH by two names, OPEN by OK.
    let id_of = |n: usize| u32::try_from(n).unwrap();
    fake.rule(Rule::new(FXP_STAT, Action::Raw(raw(FXP_HANDLE, id_of(1), &crate::fake::string(b"h")))).once());
    let e = client.stat(b"/", true, &c).await.unwrap_err();
    assert_eq!(e, unexpected());
    let two = [2u32.to_be_bytes().to_vec(), crate::fake::string(b"a"), crate::fake::string(b""), vec![0; 4], crate::fake::string(b"b"), crate::fake::string(b""), vec![0; 4]].concat();
    fake.rule(Rule::new(FXP_REALPATH, Action::Raw(raw(FXP_NAME, id_of(2), &two))).once());
    assert_eq!(client.path_of(PathOf::Realpath(b"."), &c).await.unwrap_err(), unexpected());
    fake.rule(Rule::new(FXP_OPEN, Action::Status(FX_OK, "")).once());
    assert_eq!(client.open(b"/x", FXF_READ, &Attrs::default(), &c).await.unwrap_err(), unexpected());
    fake.rule(Rule::new(FXP_READDIR, Action::Raw(raw(FXP_ATTRS, id_of(4), &[0, 0, 0, 0]))).once());
    assert_eq!(client.readdir(b"h", &c).await.unwrap_err(), unexpected());
    fake.rule(Rule::new(FXP_REMOVE, Action::Raw(raw(FXP_ATTRS, id_of(5), &[0, 0, 0, 0]))).once());
    assert_eq!(client.simple(Simple::Remove(b"/x"), &c).await.unwrap_err(), unexpected());
    // A status that is not OK where a value was wanted is the server's.
    fake.rule(Rule::new(FXP_FSTAT, Action::Status(FX_FAILURE, "no")).once());
    let e = client.fstat(b"h", &c).await.unwrap_err();
    assert_eq!(e, Failure::Server(StatusReply { code: FX_FAILURE, message: "no".into() }));
    assert!(!client.is_ended());
}

#[tokio::test]
async fn timeouts_and_cancels_abandon_the_request() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Delay(Duration::from_millis(200))).once());
    let (client, _, _) = start_with(&fake, Duration::from_millis(50)).await;
    let c = CancelToken::new();
    let e = client.stat(b"/", true, &c).await.unwrap_err();
    assert_eq!(e.status("x"), timed_out(50));
    assert_eq!(client.shared.table().abandoned, 1);
    // The late reply is dropped when it comes, and the client goes on.
    eventually(|| client.shared.table().abandoned == 0).await;
    assert!(client.shared.table().slots.is_empty());
    client.stat(b"/", true, &c).await.unwrap();

    fake.rule(Rule::new(FXP_STAT, Action::Ignore).once());
    let canceled = CancelToken::new();
    let trip = canceled.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        trip.cancel();
    });
    let started = std::time::Instant::now();
    let e = client.stat(b"/", true, &canceled).await.unwrap_err();
    assert_eq!(e, Failure::Local(Status::canceled()));
    assert!(started.elapsed() < Duration::from_millis(45));
    assert_eq!(client.shared.table().abandoned, 1);
}

#[tokio::test]
async fn a_canceled_request_whose_reply_is_there_gives_the_reply() {
    let fake = Fake::new();
    let client = start(&fake).await;
    let c = CancelToken::new();
    let pending = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    eventually(|| client.shared.table().slots.is_empty()).await;
    c.cancel();
    assert!(matches!(pending.wait(&c).await, Ok(Reply::Attrs(_))));
    assert_eq!(client.shared.table().abandoned, 0);
}

#[tokio::test]
async fn an_abandoned_open_closes_its_handle() {
    let fake = Fake::new();
    fake.file("/home/u/a", b"x");
    fake.rule(Rule::new(FXP_OPEN, Action::Delay(Duration::from_millis(30))).once());
    let client = start(&fake).await;
    let c = CancelToken::new();
    c.cancel();
    // Canceled before the reply: the handle that comes later is closed.
    let e = client.open(b"/home/u/a", FXF_READ, &Attrs::default(), &c).await.unwrap_err();
    assert_eq!(e, Failure::Local(Status::canceled()));
    eventually(|| fake.requests(FXP_CLOSE).len() == 1).await;
    eventually(|| fake.open_handles() == 0 && client.shared.table().slots.is_empty()).await;
    assert_eq!(client.shared.table().abandoned, 0);

    // Dropped after the reply arrived but before it was taken.
    let pending = client.send_as(Packet::request(FXP_OPENDIR).string(b"/home/u"), true).unwrap();
    eventually(|| client.shared.table().slots.is_empty()).await;
    assert_eq!(fake.open_handles(), 1);
    drop(pending);
    eventually(|| fake.open_handles() == 0).await;
    assert_eq!(fake.requests(FXP_CLOSE).len(), 2);

    // An abandoned request of another kind closes nothing.
    let pending = client.send(Packet::request(FXP_OPENDIR).string(b"/home/u")).unwrap();
    drop(pending);
    eventually(|| client.shared.table().slots.is_empty()).await;
    assert_eq!(fake.open_handles(), 1);
    assert_eq!(fake.requests(FXP_CLOSE).len(), 2);
    // A detached close goes out and its reply is dropped.
    client.close_detached(b"h3");
    eventually(|| fake.open_handles() == 0 && client.shared.table().slots.is_empty()).await;
    assert_eq!(client.shared.table().abandoned, 0);
}

#[tokio::test]
async fn too_many_abandoned_requests_end_the_client() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Ignore));
    let (client, _, ended) = start_with(&fake, LONG).await;
    for _ in 0..MAX_ABANDONED {
        drop(client.send(Packet::request(FXP_STAT).string(b"/")).unwrap());
    }
    assert!(!client.is_ended());
    assert_eq!(client.shared.table().abandoned, MAX_ABANDONED);
    let waiting = client.send(Packet::request(FXP_LSTAT).string(b"/")).unwrap();
    drop(client.send(Packet::request(FXP_STAT).string(b"/")).unwrap());
    assert!(client.is_ended());
    let reason = client.end_reason();
    assert_eq!(reason.message, "The server left too many requests unanswered");
    assert_eq!(waiting.wait(&CancelToken::new()).await.unwrap_err(), Failure::Local(reason.clone()));
    assert_eq!(client.send(Packet::request(FXP_STAT)).unwrap_err(), Failure::Local(reason));
    tokio::time::timeout(LONG, ended).await.unwrap().unwrap();
}

#[tokio::test]
async fn detached_closes_count_as_abandoned() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_CLOSE, Action::Ignore));
    let client = start(&fake).await;
    for _ in 0..MAX_ABANDONED {
        client.close_detached(b"h");
    }
    assert!(!client.is_ended());
    client.close_detached(b"h");
    assert!(client.is_ended());
}

#[tokio::test]
async fn a_reply_to_no_request_ends_the_client() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Raw(raw(FXP_STATUS, 999, &[0, 0, 0, 0]))).once());
    let (client, _, ended) = start_with(&fake, LONG).await;
    let e = client.stat(b"/", true, &CancelToken::new()).await.unwrap_err();
    let s = e.status("x");
    assert_eq!((s.name, s.message.as_str(), s.detail.as_str()), (ErrorName::ProtocolError, "The server answered a request that was not sent", "id 999"));
    tokio::time::timeout(LONG, ended).await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_replies_end_the_client() {
    for bad in [
        raw(FXP_STATUS, 1, &[0, 0]),       // short
        raw(77, 1, &[]),                     // unknown type
        vec![0, 0, 0, 0],                    // empty packet
        u32::try_from(MAX_PACKET + 1).unwrap().to_be_bytes().to_vec(), // too long
    ] {
        let fake = Fake::new();
        fake.rule(Rule::new(FXP_STAT, Action::Raw(bad.clone())).once());
        let client = start(&fake).await;
        let e = client.stat(b"/", true, &CancelToken::new()).await.unwrap_err();
        assert_eq!(name(&e), ErrorName::ProtocolError, "{bad:?}");
        assert!(client.is_ended());
    }
}

#[tokio::test]
async fn a_full_size_packet_is_read() {
    let fake = Fake::new();
    let data = vec![7; MAX_PACKET - 9];
    let reply = raw(FXP_DATA, 1, &crate::fake::string(&data));
    assert_eq!(reply.len(), MAX_PACKET + 4);
    fake.rule(Rule::new(FXP_READ, Action::Raw(reply)).once());
    let client = start(&fake).await;
    let got = client.read(b"h", 0, 1).unwrap().wait(&CancelToken::new()).await.unwrap();
    assert_eq!(got, Reply::Data(data));
}

#[tokio::test]
async fn a_hangup_fails_waiting_and_later_requests() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Hangup));
    let (client, _, ended) = start_with(&fake, LONG).await;
    let c = CancelToken::new();
    let lost = Failure::Local(connection_lost().with_detail("early eof"));
    assert_eq!(client.stat(b"/", true, &c).await.unwrap_err(), lost);
    assert_eq!(client.stat(b"/", true, &c).await.unwrap_err(), lost);
    assert!(client.is_ended());
    tokio::time::timeout(LONG, ended).await.unwrap().unwrap();
}

#[tokio::test]
async fn ending_fails_waiters_with_the_reason_and_closes_the_channel() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Ignore));
    let (client, _, ended) = start_with(&fake, LONG).await;
    let waiting = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    assert_eq!(client.end_reason(), connection_lost());
    client.end(crate::errors::connection_closed());
    client.end(Status::internal("second reason loses"));
    assert_eq!(waiting.wait(&CancelToken::new()).await.unwrap_err(), Failure::Local(crate::errors::connection_closed()));
    assert_eq!(client.end_reason(), crate::errors::connection_closed());
    tokio::time::timeout(LONG, ended).await.unwrap().unwrap();
    assert_eq!(client.timeout(), LONG);
}

#[tokio::test]
async fn requests_too_long_for_a_packet_are_refused() {
    let fake = Fake::new();
    let client = start(&fake).await;
    let long = vec![b'a'; MAX_PACKET];
    let e = client.stat(&long, true, &CancelToken::new()).await.unwrap_err();
    assert_eq!(name(&e), ErrorName::InvalidName);
    assert!(!client.is_ended());
    assert!(client.shared.table().slots.is_empty());
}

#[tokio::test]
async fn ids_skip_those_still_in_use() {
    let fake = Fake::new();
    fake.rule(Rule::new(FXP_STAT, Action::Ignore));
    let client = start(&fake).await;
    let first = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    assert_eq!(first.id, 1);
    client.shared.table().next_id = 1;
    let second = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    assert_eq!(second.id, 2);
    client.shared.table().next_id = u32::MAX;
    let third = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    assert_eq!(third.id, u32::MAX);
    let fourth = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    assert_eq!(fourth.id, 0);
}

#[tokio::test]
async fn waiting_twice_is_an_internal_error() {
    let fake = Fake::new();
    let client = start(&fake).await;
    let mut pending = client.send(Packet::request(FXP_STAT).string(b"/")).unwrap();
    let rx = pending.rx.take();
    let e = pending.wait(&CancelToken::new()).await.unwrap_err();
    assert_eq!(e, Failure::Local(Status::internal("The request was already answered")));
    drop(rx);
}
