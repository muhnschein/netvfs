// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, reason = "tests")]

use super::*;
use crate::fake::{Action, Fake, Node, Rule, encode_attrs, string};
use crate::proto::{
    FX_FAILURE, FX_PERMISSION_DENIED, FXP_ATTRS, FXP_CLOSE, FXP_DATA, FXP_EXTENDED, FXP_FSTAT, FXP_OPEN,
    FXP_READ, FXP_SETSTAT, FXP_WRITE,
};
use crate::remote::Remote;
use std::time::Duration;

fn cancel() -> CancelToken {
    CancelToken::new()
}

fn err<T: std::fmt::Debug>(r: Result<T, Status>) -> (ErrorName, String) {
    let e = r.unwrap_err();
    (e.name, e.message)
}

fn named(name: ErrorName, message: &str) -> (ErrorName, String) {
    (name, message.to_owned())
}

async fn eventually(mut check: impl FnMut() -> bool) {
    for _ in 0..500 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("condition not reached");
}

#[derive(Debug, Default)]
struct Recorder {
    updates: Vec<(u64, Option<u64>)>,
    stop_after: Option<usize>,
}

impl Progress for Recorder {
    fn update(&mut self, done: u64, total: Option<u64>) {
        self.updates.push((done, total));
    }

    fn canceled(&mut self) -> bool {
        self.stop_after.is_some_and(|n| self.updates.len() >= n)
    }
}

struct Bytes {
    data: Vec<u8>,
    at: usize,
    step: usize,
    fail_at: Option<usize>,
    size: Option<u64>,
    ends: usize,
}

impl Bytes {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            at: 0,
            step: usize::MAX,
            fail_at: None,
            size: Some(data.len() as u64),
            ends: 0,
        }
    }
}

impl Source for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        if self.fail_at.is_some_and(|f| self.at >= f) {
            return Err(Status::new(ErrorName::Internal, "source failed"));
        }
        let n = buf.len().min(self.step).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        if n == 0 {
            self.ends += 1;
        }
        Ok(n)
    }

    fn size(&self) -> Option<u64> {
        self.size
    }
}

#[derive(Debug, Default)]
struct Collect {
    data: Vec<u8>,
    writes: usize,
    fail_after: Option<usize>,
}

impl Sink for Collect {
    fn write(&mut self, data: &[u8]) -> Result<(), Status> {
        if self.fail_after.is_some_and(|n| self.writes >= n) {
            return Err(Status::new(ErrorName::Internal, "sink failed"));
        }
        self.writes += 1;
        self.data.extend_from_slice(data);
        Ok(())
    }
}

fn digits(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'0' + (i % 10) as u8).collect()
}

async fn setup() -> (Fake, Remote) {
    let fake = Fake::new();
    let remote = fake.remote().await;
    fake.take_log();
    (fake, remote)
}

async fn upload(
    remote: &Remote,
    path: &[u8],
    options: &WriteOptions,
    source: &mut Bytes,
) -> Result<Recorder, Status> {
    let mut progress = Recorder::default();
    let up = Upload { client: remote.client(), ext: remote.extensions(), chunk: 4 };
    up.run(path, options, source, &mut progress, &cancel()).await.map(|()| progress)
}

fn create_new() -> WriteOptions {
    WriteOptions::default()
}

fn with(disposition: Disposition) -> WriteOptions {
    WriteOptions { disposition, ..WriteOptions::default() }
}

#[tokio::test]
async fn upload_in_chunks_then_fsync_and_close() {
    let (fake, remote) = setup().await;
    let progress =
        upload(&remote, b"/home/u/new", &create_new(), &mut Bytes::new(b"0123456789")).await.unwrap();
    assert_eq!(fake.data("/home/u/new"), Some(b"0123456789".to_vec()));
    assert_eq!(progress.updates, [(4, Some(10)), (8, Some(10)), (10, Some(10))]);
    assert_eq!(fake.kinds(), ["OPEN", "WRITE", "WRITE", "WRITE", "fsync@openssh.com", "CLOSE"]);
    let open = &fake.requests(FXP_OPEN)[0];
    assert_eq!(open.pflags, Some(FXF_WRITE | FXF_CREAT | FXF_EXCL));
    assert_eq!(open.attrs, Some(Attrs { permissions: Some(0o666), ..Attrs::default() }));
    let writes: Vec<(Option<u64>, Vec<u8>)> =
        fake.requests(FXP_WRITE).into_iter().map(|w| (w.offset, w.strings[1].clone())).collect();
    assert_eq!(writes, [(Some(0), b"0123".to_vec()), (Some(4), b"4567".to_vec()), (Some(8), b"89".to_vec())]);
    let handle = &open.strings;
    assert_eq!(handle, &[b"/home/u/new".to_vec()]);
    assert_eq!(fake.requests(FXP_EXTENDED)[0].strings, fake.requests(FXP_CLOSE)[0].strings);
    assert_eq!(fake.open_handles(), 0);
}

#[tokio::test]
async fn upload_reads_the_source_until_its_end() {
    let (fake, remote) = setup().await;
    let mut source = Bytes { step: 1, size: None, ..Bytes::new(b"abcdefghij") };
    let progress = upload(&remote, b"/home/u/new", &create_new(), &mut source).await.unwrap();
    assert_eq!(fake.data("/home/u/new"), Some(b"abcdefghij".to_vec()));
    assert_eq!(progress.updates, [(4, None), (8, None), (10, None)]);
    assert_eq!(fake.requests(FXP_WRITE).len(), 3);
    assert_eq!(source.ends, 1);
    upload(&remote, b"/home/u/empty", &create_new(), &mut Bytes::new(b"")).await.unwrap();
    assert_eq!(fake.data("/home/u/empty"), Some(Vec::new()));
    assert_eq!(fake.requests(FXP_WRITE).len(), 3);
}

#[tokio::test]
async fn upload_dispositions() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", b"old content");
    fake.dir("/home/u/d");
    assert_eq!(
        err(upload(&remote, b"/home/u/f", &create_new(), &mut Bytes::new(b"x")).await),
        named(ErrorName::AlreadyExists, "/home/u/f exists")
    );
    assert_eq!(
        err(upload(&remote, b"/home/u/d", &with(Disposition::Truncate), &mut Bytes::new(b"x")).await),
        named(ErrorName::IsADirectory, "/home/u/d is a folder")
    );
    assert_eq!(
        err(upload(&remote, b"/home/u/no/f", &create_new(), &mut Bytes::new(b"x")).await),
        named(ErrorName::NotFound, "/home/u/no/f: not found")
    );
    upload(&remote, b"/home/u/f", &with(Disposition::Truncate), &mut Bytes::new(b"new")).await.unwrap();
    assert_eq!(fake.data("/home/u/f"), Some(b"new".to_vec()));
    assert_eq!(fake.requests(FXP_OPEN).last().unwrap().pflags, Some(FXF_WRITE | FXF_CREAT | FXF_TRUNC));
    fake.rule(Rule::new(FXP_OPEN, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    assert_eq!(
        err(upload(&remote, b"/home/u/f", &with(Disposition::Truncate), &mut Bytes::new(b"x")).await),
        named(ErrorName::PermissionDenied, "/home/u/f: permission denied")
    );

    let resume =
        WriteOptions { disposition: Disposition::Resume, resume_offset: 3, ..WriteOptions::default() };
    let progress = upload(&remote, b"/home/u/f", &resume, &mut Bytes::new(b"-more")).await.unwrap();
    assert_eq!(fake.data("/home/u/f"), Some(b"new-more".to_vec()));
    assert_eq!(fake.requests(FXP_OPEN).last().unwrap().pflags, Some(FXF_WRITE));
    assert_eq!(progress.updates, [(7, Some(8)), (8, Some(8))]);
    let offsets: Vec<Option<u64>> = fake.requests(FXP_WRITE).iter().rev().take(2).map(|w| w.offset).collect();
    assert_eq!(offsets, [Some(7), Some(3)]);

    let wrong =
        WriteOptions { disposition: Disposition::Resume, resume_offset: 3, ..WriteOptions::default() };
    let writes = fake.requests(FXP_WRITE).len();
    assert_eq!(
        err(upload(&remote, b"/home/u/f", &wrong, &mut Bytes::new(b"x")).await),
        named(ErrorName::ProtocolError, "Cannot resume at 3: the file has 8 bytes")
    );
    assert_eq!(fake.requests(FXP_WRITE).len(), writes);
    eventually(|| fake.open_handles() == 0).await;
    assert_eq!(
        err(upload(&remote, b"/home/u/g", &wrong, &mut Bytes::new(b"x")).await).0,
        ErrorName::NotFound
    );
}

#[tokio::test]
async fn upload_mode_and_modification_time() {
    let (fake, remote) = setup().await;
    let options =
        WriteOptions { create_mode: Some(0o104_640), mtime_ms: Some(9_000_500), ..WriteOptions::default() };
    upload(&remote, b"/home/u/f", &options, &mut Bytes::new(b"x")).await.unwrap();
    assert_eq!(
        fake.requests(FXP_OPEN)[0].attrs,
        Some(Attrs { permissions: Some(0o4640), ..Attrs::default() })
    );
    assert_eq!(fake.kinds()[3..], ["CLOSE", "STAT", "SETSTAT"]);
    assert_eq!(
        fake.node("/home/u/f"),
        Some(Node::File { data: b"x".to_vec(), mode: 0o4640, mtime: 9000, atime: 5000 })
    );
}

#[tokio::test]
async fn upload_without_fsync() {
    let fake = Fake::new().with_extensions(&[]);
    let remote = fake.remote().await;
    fake.take_log();
    upload(&remote, b"/home/u/f", &create_new(), &mut Bytes::new(b"x")).await.unwrap();
    assert_eq!(fake.kinds(), ["OPEN", "WRITE", "CLOSE"]);
}

#[tokio::test]
async fn upload_failures() {
    let (fake, remote) = setup().await;
    fake.state().statvfs[1] = 1;
    fake.state().statvfs[4] = 3;
    fake.rule(Rule::new(FXP_WRITE, Action::Status(FX_FAILURE, "Failure")).once());
    assert_eq!(
        err(upload(&remote, b"/home/u/a", &create_new(), &mut Bytes::new(&digits(10_000))).await),
        named(ErrorName::NoSpace, "The server has no space left for /home/u/a")
    );
    eventually(|| fake.open_handles() == 0).await;
    fake.state().statvfs[4] = 4;
    fake.rule(Rule::new(FXP_WRITE, Action::Status(FX_FAILURE, "Failure")).once());
    assert_eq!(
        err(upload(&remote, b"/home/u/b", &create_new(), &mut Bytes::new(b"x")).await),
        named(ErrorName::ProtocolError, "/home/u/b: Failure")
    );
    let mut source = Bytes { fail_at: Some(8), ..Bytes::new(&digits(20)) };
    assert_eq!(
        err(upload(&remote, b"/home/u/c", &create_new(), &mut source).await),
        named(ErrorName::Internal, "source failed")
    );
    eventually(|| fake.open_handles() == 0).await;
    fake.rule(Rule::ext("fsync@openssh.com", Action::Status(FX_PERMISSION_DENIED, "no")).once());
    assert_eq!(
        err(upload(&remote, b"/home/u/d", &create_new(), &mut Bytes::new(b"x")).await),
        named(ErrorName::PermissionDenied, "/home/u/d: permission denied")
    );
    eventually(|| fake.open_handles() == 0).await;
    fake.rule(Rule::new(FXP_CLOSE, Action::Status(FX_FAILURE, "Failure")).once());
    fake.state().statvfs[4] = 0;
    assert_eq!(
        err(upload(&remote, b"/home/u/e", &create_new(), &mut Bytes::new(b"x")).await),
        named(ErrorName::NoSpace, "The server has no space left for /home/u/e")
    );
    assert_eq!(fake.requests(FXP_SETSTAT), []);
}

#[tokio::test]
async fn upload_is_canceled() {
    let (fake, remote) = setup().await;
    let up = Upload { client: remote.client(), ext: remote.extensions(), chunk: 4 };
    let mut progress = Recorder { stop_after: Some(2), ..Recorder::default() };
    let e = up
        .run(b"/home/u/f", &create_new(), &mut Bytes::new(&digits(100)), &mut progress, &cancel())
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(progress.updates.len(), 2);
    eventually(|| fake.open_handles() == 0).await;
    let c = cancel();
    c.cancel();
    let mut progress = Recorder::default();
    let e = up.run(b"/home/u/g", &create_new(), &mut Bytes::new(b"x"), &mut progress, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(fake.node("/home/u/g"), None);
}

#[tokio::test]
async fn upload_keeps_sixteen_writes_in_flight() {
    let (fake, remote) = setup().await;
    fake.rule(Rule::new(FXP_WRITE, Action::Ignore).once());
    let c = cancel();
    let trip = c.clone();
    let watcher = fake.clone();
    let stop = tokio::spawn(async move {
        eventually(|| watcher.requests(FXP_WRITE).len() >= WINDOW).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let sent = watcher.requests(FXP_WRITE).len();
        trip.cancel();
        sent
    });
    let up = Upload { client: remote.client(), ext: remote.extensions(), chunk: 4 };
    let e = up
        .run(b"/home/u/f", &create_new(), &mut Bytes::new(&digits(400)), &mut Recorder::default(), &c)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(stop.await.unwrap(), WINDOW);
}

async fn download(
    remote: &Remote,
    path: &[u8],
    offset: u64,
    length: Option<u64>,
) -> Result<(Vec<u8>, Recorder), Status> {
    let mut sink = Collect::default();
    let mut progress = Recorder::default();
    let down = Download { client: remote.client(), chunk: 4 };
    down.run(path, offset, length, &mut sink, &mut progress, &cancel()).await.map(|()| (sink.data, progress))
}

#[tokio::test]
async fn download_whole_and_ranges() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", b"0123456789");
    let (data, progress) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!(data, b"0123456789");
    assert_eq!(progress.updates, [(4, Some(10)), (8, Some(10)), (10, Some(10))]);
    assert_eq!(reads(&fake), [(0, 4), (4, 4), (8, 4), (10, 2)]);
    assert_eq!(fake.requests(FXP_OPEN)[0].pflags, Some(FXF_READ));
    eventually(|| fake.open_handles() == 0).await;
    fake.take_log();

    let (data, progress) = download(&remote, b"/home/u/f", 3, Some(5)).await.unwrap();
    assert_eq!(data, b"34567");
    assert_eq!(progress.updates, [(4, Some(5)), (5, Some(5))]);
    assert_eq!(reads(&fake), [(3, 4), (7, 1)]);
    fake.take_log();

    let (data, progress) = download(&remote, b"/home/u/f", 8, Some(100)).await.unwrap();
    assert_eq!((data.as_slice(), progress.updates.as_slice()), (&b"89"[..], &[(2, Some(2))][..]));
    assert_eq!(reads(&fake), [(8, 4), (10, 2)]);
    fake.take_log();
    let (data, progress) = download(&remote, b"/home/u/f", 20, None).await.unwrap();
    assert_eq!((data.as_slice(), progress.updates.as_slice()), (&b""[..], &[][..]));
    assert_eq!(reads(&fake), [(20, 4)]);
    fake.take_log();
    let (data, _) = download(&remote, b"/home/u/f", 2, Some(0)).await.unwrap();
    assert_eq!(data, b"");
    assert_eq!(fake.requests(FXP_READ), []);
    assert_eq!(
        err(download(&remote, b"/home/u/f", u64::MAX, Some(1)).await),
        named(ErrorName::Internal, "Invalid range")
    );
    assert_eq!(fake.requests(FXP_OPEN).len(), 1);
    eventually(|| fake.open_handles() == 0).await;
}

#[tokio::test]
async fn download_keeps_the_window_full_and_follows_a_growing_file() {
    let (fake, remote) = setup().await;
    let content = digits(200);
    fake.file("/home/u/f", &content);
    fake.rule(Rule::new(FXP_READ, Action::Delay(Duration::from_millis(50))).once());
    let (data, _) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!(data, content);
    let first: Vec<(u64, u32)> = reads(&fake).into_iter().take(WINDOW).collect();
    let expected: Vec<(u64, u32)> = (0..WINDOW as u64).map(|i| (i * 4, 4)).collect();
    assert_eq!(first, expected);
    assert_eq!(reads(&fake).len(), 51);
    fake.take_log();

    let opened = Attrs { size: Some(8), permissions: Some(0o100_644), ..Attrs::default() };
    fake.rule(Rule::new(FXP_FSTAT, Action::Reply(FXP_ATTRS, encode_attrs(&opened))).once());
    let (data, progress) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!(data, content);
    assert_eq!(progress.updates[..3], [(4, Some(8)), (8, Some(8)), (12, Some(8))]);
    let offsets: Vec<u64> = reads(&fake).into_iter().map(|(o, _)| o).collect();
    assert_eq!(offsets[..3], [0, 4, 8]);
    let window: Vec<u64> = (0..WINDOW as u64).map(|i| 12 + 4 * i).collect();
    assert_eq!(offsets[3..3 + WINDOW], window);
}

#[tokio::test]
async fn download_keeps_sixteen_reads_in_flight() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", &digits(400));
    fake.rule(Rule::new(FXP_READ, Action::Ignore).once());
    let c = cancel();
    let trip = c.clone();
    let watcher = fake.clone();
    let stop = tokio::spawn(async move {
        eventually(|| watcher.requests(FXP_READ).len() >= WINDOW).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let sent = watcher.requests(FXP_READ).len();
        trip.cancel();
        sent
    });
    let down = Download { client: remote.client(), chunk: 4 };
    let mut sink = Collect::default();
    let e = down.run(b"/home/u/f", 0, None, &mut sink, &mut Recorder::default(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(stop.await.unwrap(), WINDOW);
    assert_eq!(sink.data, b"");
}

#[tokio::test]
async fn download_finds_the_end_once_the_rest_has_come() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", b"01234567");
    fake.rule(Rule::new(FXP_READ, Action::Delay(Duration::from_millis(200))).once());
    let watcher = fake.clone();
    let seen = tokio::spawn(async move {
        eventually(|| watcher.requests(FXP_READ).len() >= 2).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        watcher.requests(FXP_READ).len()
    });
    let (data, _) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!(data, b"01234567");
    assert_eq!(seen.await.unwrap(), 2);
    assert_eq!(reads(&fake), [(0, 4), (4, 4), (8, 4)]);
}

#[tokio::test]
async fn download_survives_short_reads() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", &digits(50));
    fake.rule(Rule::new(FXP_READ, Action::ShortRead(3)).once());
    let (data, _) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!(data, digits(50));
    let reads = fake.requests(FXP_READ);
    assert!(reads.iter().any(|r| r.offset == Some(3)), "{reads:?}");
    fake.rule(Rule::new(FXP_READ, Action::ShortRead(1)));
    let (data, _) = download(&remote, b"/home/u/f", 7, Some(30)).await.unwrap();
    assert_eq!(data, digits(50)[7..37]);
}

#[tokio::test]
async fn download_refusals() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", b"0123456789");
    fake.dir("/home/u/d");
    assert_eq!(
        err(download(&remote, b"/home/u/d", 0, None).await),
        named(ErrorName::IsADirectory, "/home/u/d is a folder")
    );
    assert_eq!(
        err(download(&remote, b"/home/u/g", 0, None).await),
        named(ErrorName::NotFound, "/home/u/g: not found")
    );
    fake.rule(Rule::new(FXP_READ, Action::Reply(FXP_DATA, string(b"12345"))).once());
    assert_eq!(
        err(download(&remote, b"/home/u/f", 0, None).await),
        named(ErrorName::ProtocolError, "The server sent more data than asked for")
    );
    fake.rule(Rule::new(FXP_READ, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    assert_eq!(
        err(download(&remote, b"/home/u/f", 0, None).await),
        named(ErrorName::PermissionDenied, "/home/u/f: permission denied")
    );
    fake.rule(Rule::new(FXP_READ, Action::Reply(FXP_DATA, string(b""))).once());
    assert_eq!(download(&remote, b"/home/u/f", 0, None).await.unwrap().0, b"");
    fake.rule(Rule::new(FXP_FSTAT, Action::Status(FX_FAILURE, "no")).once());
    let (data, progress) = download(&remote, b"/home/u/f", 0, None).await.unwrap();
    assert_eq!((data.as_slice(), progress.updates[0]), (&b"0123456789"[..], (4, None)));
    eventually(|| fake.open_handles() == 0).await;
    fake.rule(Rule::new(FXP_FSTAT, Action::Hangup).once());
    assert_eq!(err(download(&remote, b"/home/u/f", 0, None).await).0, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn download_stops_for_the_sink_and_cancel() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", &digits(100));
    let down = Download { client: remote.client(), chunk: 4 };
    let mut sink = Collect { fail_after: Some(2), ..Collect::default() };
    let e =
        down.run(b"/home/u/f", 0, None, &mut sink, &mut Recorder::default(), &cancel()).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Internal, "sink failed"));
    assert_eq!(sink.data, digits(8));
    eventually(|| fake.open_handles() == 0).await;
    let mut progress = Recorder { stop_after: Some(3), ..Recorder::default() };
    let mut sink = Collect::default();
    let e = down.run(b"/home/u/f", 0, None, &mut sink, &mut progress, &cancel()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(sink.data, digits(12));
    eventually(|| fake.open_handles() == 0).await;
    let c = cancel();
    c.cancel();
    let e = down.run(b"/home/u/f", 0, None, &mut sink, &mut Recorder::default(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(fake.requests(FXP_OPEN).len(), 2);
}

async fn reader(fake: &Fake, remote: &Remote, path: &[u8], chunk: u32) -> SftpRead {
    let (handle, size) = open_for_read(remote.client(), path, &cancel()).await.unwrap();
    fake.take_log();
    SftpRead::new(remote.client().clone(), handle, path.to_vec(), size, chunk)
}

async fn read(h: &mut SftpRead, offset: u64, len: usize) -> Result<Vec<u8>, Status> {
    let mut buf = vec![0; len];
    let n = h.read(offset, &mut buf, &cancel()).await?;
    buf.truncate(n);
    Ok(buf)
}

fn reads(fake: &Fake) -> Vec<(u64, u32)> {
    fake.requests(FXP_READ).into_iter().map(|r| (r.offset.unwrap(), r.len.unwrap())).collect()
}

async fn offsets_become(fake: &Fake, expected: &[u64]) {
    for _ in 0..500 {
        if read_offsets(fake) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(read_offsets(fake), expected);
}

async fn reads_become(fake: &Fake, expected: &[(u64, u32)]) {
    for _ in 0..500 {
        if reads(fake) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(reads(fake), expected);
}

fn read_offsets(fake: &Fake) -> Vec<u64> {
    fake.requests(FXP_READ).into_iter().map(|r| r.offset.unwrap()).collect()
}

#[tokio::test]
async fn read_window_follows_the_chunk() {
    let (_fake, remote) = setup().await;
    let window =
        |chunk| SftpRead::new(remote.client().clone(), b"h".to_vec(), Vec::new(), None, chunk).window;
    assert_eq!(window(4), WINDOW);
    assert_eq!(window(256 * 1024), 16);
    assert_eq!(window(512 * 1024), 8);
    assert_eq!(window(1024 * 1024 + 1), 3);
    assert_eq!(window(u32::MAX), 1);
    assert_eq!(window(0), WINDOW);
}

#[tokio::test]
async fn read_handle_reads_ahead_while_sequential() {
    let (fake, remote) = setup().await;
    let content = digits(200);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    assert_eq!(h.size(), Some(200));
    assert_eq!(read(&mut h, 0, 4).await.unwrap(), content[..4]);
    assert_eq!(read_offsets(&fake), [0]);
    assert_eq!(read(&mut h, 4, 4).await.unwrap(), content[4..8]);
    offsets_become(&fake, &[0, 4, 8]).await;
    assert_eq!(read(&mut h, 8, 4).await.unwrap(), content[8..12]);
    offsets_become(&fake, &[0, 4, 8, 12, 16]).await;
    for at in (12..60).step_by(4) {
        assert_eq!(read(&mut h, at, 4).await.unwrap(), content[at as usize..at as usize + 4]);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let offsets = read_offsets(&fake);
    assert_eq!(offsets.last(), Some(&(56 + 15 * 4)));
    let mut unique = offsets.clone();
    unique.dedup();
    assert_eq!(unique, offsets, "each chunk is asked for once");
    fake.take_log();
    assert_eq!(read(&mut h, 150, 4).await.unwrap(), content[150..154]);
    assert_eq!(read_offsets(&fake), [150]);
    for at in (154..198).step_by(4) {
        assert_eq!(read(&mut h, at, 4).await.unwrap(), content[at as usize..at as usize + 4]);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(read_offsets(&fake).iter().all(|&o| o < 200), "{:?}", read_offsets(&fake));
    assert_eq!(read(&mut h, 198, 4).await.unwrap(), content[198..]);
    assert_eq!(read(&mut h, 200, 4).await.unwrap(), b"");
    h.close(&cancel()).await.unwrap();
    eventually(|| fake.open_handles() == 0).await;
}

#[tokio::test]
async fn read_handle_keeps_what_a_reply_brought_beyond_the_read() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
    assert_eq!(read(&mut h, 0, 3).await.unwrap(), content[..3]);
    assert_eq!(reads(&fake), [(0, 3)]);
    assert_eq!(read(&mut h, 3, 3).await.unwrap(), content[3..6]);
    reads_become(&fake, &[(0, 3), (3, 8), (11, 3)]).await;
    assert_eq!(read(&mut h, 6, 5).await.unwrap(), content[6..11]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(reads(&fake).len(), 3);
    assert_eq!(read(&mut h, 11, 3).await.unwrap(), content[11..14]);
    reads_become(&fake, &[(0, 3), (3, 8), (11, 3), (14, 8), (22, 8), (30, 8), (38, 2)]).await;
    assert_eq!(read(&mut h, 14, 10).await.unwrap(), content[14..24]);
    fake.take_log();
    assert_eq!(read(&mut h, 1, 2).await.unwrap(), content[1..3]);
    assert_eq!(reads(&fake), [(1, 2)]);
}

#[tokio::test]
async fn read_handle_hands_out_kept_data_in_parts() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
    assert_eq!(read(&mut h, 0, 3).await.unwrap(), content[..3]);
    assert_eq!(read(&mut h, 3, 3).await.unwrap(), content[3..6]);
    reads_become(&fake, &[(0, 3), (3, 8), (11, 3)]).await;
    assert_eq!(read(&mut h, 6, 2).await.unwrap(), content[6..8]);
    assert_eq!(read(&mut h, 8, 3).await.unwrap(), content[8..11]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(reads(&fake), [(0, 3), (3, 8), (11, 3)]);
}

#[tokio::test]
async fn read_ahead_hints_and_the_kept_data() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let kept = || async {
        let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
        h.read_ahead(0, 8);
        assert_eq!(read(&mut h, 0, 3).await.unwrap(), content[..3]);
        assert_eq!(reads(&fake), [(0, 8)]);
        h
    };
    let mut h = kept().await;
    h.read_ahead(1, 4);
    reads_become(&fake, &[(0, 8), (1, 4)]).await;
    assert_eq!(read(&mut h, 1, 4).await.unwrap(), content[1..5]);
    let mut h = kept().await;
    h.read_ahead(8, 4);
    reads_become(&fake, &[(0, 8), (8, 4)]).await;
    assert_eq!(read(&mut h, 3, 9).await.unwrap(), content[3..12]);
    reads_become(&fake, &[(0, 8), (8, 4), (12, 8)]).await;
    let mut h = kept().await;
    h.read_ahead(3, 9);
    reads_become(&fake, &[(0, 8), (8, 4)]).await;
    assert_eq!(read(&mut h, 3, 9).await.unwrap(), content[3..12]);
    reads_become(&fake, &[(0, 8), (8, 4), (12, 8)]).await;
    let mut h = kept().await;
    h.read_ahead(20, 4);
    reads_become(&fake, &[(0, 8), (20, 4)]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(reads(&fake), [(0, 8), (20, 4)]);
    assert_eq!(read(&mut h, 20, 4).await.unwrap(), content[20..24]);
}

#[tokio::test]
async fn reads_the_kept_data_answers_leave_the_requests_on_their_way() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
    h.read_ahead(0, 16);
    reads_become(&fake, &[(0, 8), (8, 8)]).await;
    assert_eq!(read(&mut h, 0, 3).await.unwrap(), content[..3]);
    assert_eq!(read(&mut h, 3, 2).await.unwrap(), content[3..5]);
    assert_eq!(read(&mut h, 5, 3).await.unwrap(), content[5..8]);
    assert_eq!(read(&mut h, 8, 8).await.unwrap(), content[8..16]);
    assert_eq!(reads(&fake).iter().filter(|&&(offset, _)| offset == 8).count(), 1, "{:?}", reads(&fake));
}

#[tokio::test]
async fn a_hint_beyond_a_read_does_not_stretch_it() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
    h.read_ahead(20, 4);
    reads_become(&fake, &[(20, 4)]).await;
    assert_eq!(read(&mut h, 0, 3).await.unwrap(), content[..3]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(reads(&fake), [(20, 4), (0, 3)]);
}

#[tokio::test]
async fn read_handle_at_the_end() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", &digits(10));
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    assert_eq!(read(&mut h, 8, 10).await.unwrap(), b"89");
    assert_eq!(read(&mut h, 10, 4).await.unwrap(), b"");
    assert_eq!(read(&mut h, 50, 4).await.unwrap(), b"");
    assert_eq!(read(&mut h, 0, 10).await.unwrap(), digits(10));
    fake.take_log();
    assert_eq!(read(&mut h, 3, 0).await.unwrap(), b"");
    assert_eq!(fake.requests(FXP_READ), []);
    let mut buf = [0; 2];
    assert_eq!(err(h.read(u64::MAX, &mut buf, &cancel()).await), named(ErrorName::Internal, "Invalid range"));
}

#[tokio::test]
async fn read_handle_with_short_answers() {
    let (fake, remote) = setup().await;
    let content = digits(100);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 8).await;
    fake.rule(Rule::new(FXP_READ, Action::ShortRead(3)));
    let mut got = Vec::new();
    while got.len() < 100 {
        let at = got.len() as u64;
        let part = read(&mut h, at, 10).await.unwrap();
        assert_ne!(part.len(), 0);
        got.extend(part);
    }
    assert_eq!(got, content);
}

#[tokio::test]
async fn read_ahead_hints() {
    let (fake, remote) = setup().await;
    let content = digits(100);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    h.read_ahead(20, 16);
    eventually(|| fake.requests(FXP_READ).len() == 4).await;
    assert_eq!(read_offsets(&fake), [20, 24, 28, 32]);
    assert_eq!(read(&mut h, 20, 16).await.unwrap(), content[20..36]);
    assert_eq!(read_offsets(&fake), [20, 24, 28, 32]);
    h.read_ahead(36, 8);
    eventually(|| fake.requests(FXP_READ).len() == 6).await;
    h.read_ahead(80, 8);
    h.read_ahead(30, 20);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(read_offsets(&fake), [20, 24, 28, 32, 36, 40]);
    h.read_ahead(0, 0);
    assert_eq!(read(&mut h, 36, 8).await.unwrap(), content[36..44]);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    h.read_ahead(60, 8);
    h.read_ahead(68, 8);
    eventually(|| fake.requests(FXP_READ).len() == 4).await;
    assert_eq!(read_offsets(&fake), [60, 64, 68, 72]);
    assert_eq!(read(&mut h, 60, 16).await.unwrap(), content[60..76]);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    h.read_ahead(80, 8);
    h.read_ahead(80, 16);
    eventually(|| fake.requests(FXP_READ).len() == 4).await;
    assert_eq!(read_offsets(&fake), [80, 84, 88, 92]);
    assert_eq!(read(&mut h, 80, 16).await.unwrap(), content[80..96]);
    let big = digits(5 << 20);
    fake.file("/home/u/big", &big);
    let mut h = reader(&fake, &remote, b"/home/u/big", 256 * 1024).await;
    h.read_ahead(0, u64::MAX);
    eventually(|| fake.requests(FXP_READ).len() == 16).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(fake.requests(FXP_READ).len(), 16);
    assert_eq!(*read_offsets(&fake).last().unwrap(), 15 * 256 * 1024);
}

#[tokio::test]
async fn read_ahead_hint_without_bytes_is_ignored() {
    let (fake, remote) = setup().await;
    let content = digits(200);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    h.read_ahead(0, 100);
    eventually(|| fake.requests(FXP_READ).len() == WINDOW).await;
    h.read_ahead(8, 0);
    assert_eq!(read(&mut h, 0, 4).await.unwrap(), content[..4]);
    assert_eq!(read(&mut h, 4, 4).await.unwrap(), content[4..8]);
    eventually(|| fake.requests(FXP_READ).len() == WINDOW + 1).await;
    assert_eq!(*read_offsets(&fake).last().unwrap(), 64);
}

#[tokio::test]
async fn read_handle_failures() {
    let (fake, remote) = setup().await;
    let content = digits(40);
    fake.file("/home/u/f", &content);
    let mut h = reader(&fake, &remote, b"/home/u/f", 4).await;
    fake.rule(Rule::new(FXP_READ, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    assert_eq!(
        err(read(&mut h, 0, 4).await),
        named(ErrorName::PermissionDenied, "/home/u/f: permission denied")
    );
    assert_eq!(read(&mut h, 0, 8).await.unwrap(), content[..8]);
    let c = cancel();
    c.cancel();
    let mut buf = [0; 4];
    assert_eq!(h.read(8, &mut buf, &c).await.unwrap_err().name, ErrorName::Canceled);
    remote.client().end(crate::errors::connection_lost());
    assert_eq!(err(read(&mut h, 8, 4).await).0, ErrorName::ConnectionLost);
    h.read_ahead(8, 4);
    assert_eq!(h.close(&cancel()).await.unwrap_err().name, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn open_for_read_refuses_a_folder() {
    let (fake, remote) = setup().await;
    fake.dir("/home/u/d");
    let e = open_for_read(remote.client(), b"/home/u/d", &cancel()).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::IsADirectory, "/home/u/d is a folder"));
    eventually(|| fake.open_handles() == 0).await;
}

async fn writer(fake: &Fake, remote: &Remote, path: &[u8], options: &WriteOptions, chunk: u32) -> SftpWrite {
    let handle = open_for_write(remote.client(), path, options, &cancel()).await.unwrap();
    fake.take_log();
    SftpWrite::new(remote.client().clone(), *remote.extensions(), handle, path.to_vec(), options, chunk)
}

#[tokio::test]
async fn write_handle_commits() {
    let (fake, remote) = setup().await;
    let options = WriteOptions { mtime_ms: Some(4_000_000), ..WriteOptions::default() };
    let mut h = writer(&fake, &remote, b"/home/u/f", &options, 4).await;
    assert_eq!(h.position(), 0);
    h.write(b"0123456", &cancel()).await.unwrap();
    h.write(b"", &cancel()).await.unwrap();
    h.write(b"789", &cancel()).await.unwrap();
    assert_eq!(h.position(), 10);
    h.commit(&cancel()).await.unwrap();
    assert_eq!(fake.data("/home/u/f"), Some(b"0123456789".to_vec()));
    let writes: Vec<(Option<u64>, Vec<u8>)> =
        fake.requests(FXP_WRITE).into_iter().map(|w| (w.offset, w.strings[1].clone())).collect();
    assert_eq!(writes, [(Some(0), b"0123".to_vec()), (Some(4), b"456".to_vec()), (Some(7), b"789".to_vec())]);
    assert_eq!(fake.kinds()[3..], ["fsync@openssh.com", "CLOSE", "STAT", "SETSTAT"]);
    assert_eq!(fake.requests(FXP_SETSTAT)[0].attrs.unwrap().times, Some((5000, 4000)));
    assert_eq!(fake.open_handles(), 0);
}

#[tokio::test]
async fn write_handle_resumes_at_the_offset() {
    let (fake, remote) = setup().await;
    fake.file("/home/u/f", b"abc");
    let options =
        WriteOptions { disposition: Disposition::Resume, resume_offset: 3, ..WriteOptions::default() };
    let mut h = writer(&fake, &remote, b"/home/u/f", &options, 4).await;
    assert_eq!(h.position(), 3);
    h.write(b"de", &cancel()).await.unwrap();
    h.commit(&cancel()).await.unwrap();
    assert_eq!(fake.data("/home/u/f"), Some(b"abcde".to_vec()));
    assert_eq!(fake.requests(FXP_SETSTAT), []);
}

#[tokio::test]
async fn write_handle_failures_stick() {
    let (fake, remote) = setup().await;
    let mut h = writer(&fake, &remote, b"/home/u/f", &WriteOptions::default(), 4).await;
    fake.rule(Rule::new(FXP_WRITE, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    h.write(b"0123", &cancel()).await.unwrap();
    assert_eq!(
        err(h.commit(&cancel()).await),
        named(ErrorName::PermissionDenied, "/home/u/f: permission denied")
    );
    eventually(|| fake.open_handles() == 0).await;
    assert!(fake.requests(FXP_EXTENDED).is_empty(), "no fsync after a failure");

    let mut h = writer(&fake, &remote, b"/home/u/g", &WriteOptions::default(), 4).await;
    fake.rule(Rule::new(FXP_WRITE, Action::Status(FX_PERMISSION_DENIED, "no")).once());
    let denied = named(ErrorName::PermissionDenied, "/home/u/g: permission denied");
    let e = h.write(&digits(4 * (WINDOW + 1)), &cancel()).await;
    assert_eq!(err(e), denied);
    let writes = fake.requests(FXP_WRITE).len();
    assert_eq!(writes, WINDOW);
    assert_eq!(err(h.write(b"x", &cancel()).await), denied);
    assert_eq!(fake.requests(FXP_WRITE).len(), writes);
    h.abort().await;
    eventually(|| fake.open_handles() == 0).await;
}

#[tokio::test]
async fn write_handle_commit_failures() {
    let (fake, remote) = setup().await;
    let mut h = writer(&fake, &remote, b"/home/u/f", &WriteOptions::default(), 4).await;
    h.write(b"x", &cancel()).await.unwrap();
    fake.rule(Rule::new(FXP_CLOSE, Action::Status(FX_FAILURE, "Failure")).once());
    fake.state().statvfs[4] = 0;
    assert_eq!(
        err(h.commit(&cancel()).await),
        named(ErrorName::NoSpace, "The server has no space left for /home/u/f")
    );
    let mut h = writer(&fake, &remote, b"/home/u/g", &WriteOptions::default(), 4).await;
    h.write(b"x", &cancel()).await.unwrap();
    fake.rule(Rule::ext("fsync@openssh.com", Action::Status(FX_FAILURE, "Failure")).once());
    assert_eq!(
        err(h.commit(&cancel()).await),
        named(ErrorName::NoSpace, "The server has no space left for /home/u/g")
    );
    eventually(|| fake.open_handles() == 1).await;
    let mut h = writer(&fake, &remote, b"/home/u/h", &WriteOptions::default(), 4).await;
    remote.client().end(crate::errors::connection_lost());
    assert_eq!(err(h.write(b"x", &cancel()).await).0, ErrorName::ConnectionLost);
    assert_eq!(err(h.commit(&cancel()).await).0, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn write_handle_abort_closes_without_fsync() {
    let (fake, remote) = setup().await;
    let mut h = writer(&fake, &remote, b"/home/u/f", &WriteOptions::default(), 4).await;
    h.write(b"0123456789", &cancel()).await.unwrap();
    h.abort().await;
    eventually(|| fake.requests(FXP_CLOSE).len() == 1).await;
    assert_eq!(fake.requests(FXP_EXTENDED), []);
    eventually(|| fake.open_handles() == 0).await;
    let c = cancel();
    c.cancel();
    let mut h = writer(&fake, &remote, b"/home/u/g", &WriteOptions::default(), 4).await;
    assert_eq!(err(h.write(b"x", &c).await).0, ErrorName::Canceled);
    assert_eq!(fake.requests(FXP_WRITE), []);
}
