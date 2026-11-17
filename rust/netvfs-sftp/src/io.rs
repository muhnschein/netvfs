// SPDX-License-Identifier: LGPL-2.1-or-later
//! Transfers and handles: READ and WRITE pipelined in a window of [`WINDOW`] requests; a read handle reads ahead
//! while access is sequential or a hint asks for it, at most [`MAX_READ_AHEAD`] bytes in flight; a write handle's
//! errors show at a later write or at commit.

use crate::client::{Client, Field, Pending, ok};
use crate::errors::{Failure, invalid_range};
use crate::paths::display;
use crate::proto::{Attrs, FX_EOF, FXF_CREAT, FXF_EXCL, FXF_READ, FXF_TRUNC, FXF_WRITE, Reply};
use crate::remote::{DEFAULT_FILE_MODE, Extensions, MODE_BITS, WINDOW, entry_from, set_times, write_failure};
use netvfs_vfs::{
    CancelToken, Disposition, EntryType, ErrorName, Progress, ReadHandle, Sink, Source, Status, WriteHandle,
    WriteOptions,
};
use std::collections::VecDeque;

/// Bytes a read handle has in flight at most.
pub const MAX_READ_AHEAD: u64 = 4 * 1024 * 1024;

/// `Canceled` when the token or the progress says so.
fn stopped(cancel: &CancelToken, progress: &mut dyn Progress) -> Result<(), Status> {
    if cancel.is_canceled() || progress.canceled() { Err(Status::canceled()) } else { Ok(()) }
}

fn more_than_asked() -> Status {
    Status::new(ErrorName::ProtocolError, "The server sent more data than asked for")
}

/// What a READ brought: data, or the end of the file.
fn data_of(reply: Reply, asked: u32) -> Result<Option<Vec<u8>>, Failure> {
    match reply {
        Reply::Data(data) if data.len() > usize::try_from(asked).unwrap_or(usize::MAX) => {
            Err(Failure::Local(more_than_asked()))
        }
        // An empty DATA is the end as well.
        Reply::Data(data) if data.is_empty() => Ok(None),
        Reply::Data(data) => Ok(Some(data)),
        Reply::Status(s) if s.code == FX_EOF => Ok(None),
        other => Err(crate::client::not_ok(other)),
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Opens `remote` for writing as `options` say; `Resume` checks that the file has `resume_offset` bytes.
///
/// # Errors
/// `IsADirectory`, `AlreadyExists` (`CreateNew`), `ProtocolError` for a
/// resume offset that is not the size; as the server reports it.
pub async fn open_for_write(
    client: &Client,
    remote: &[u8],
    options: &WriteOptions,
    cancel: &CancelToken,
) -> Result<Vec<u8>, Status> {
    let flags = FXF_WRITE
        | match options.disposition {
            Disposition::CreateNew => FXF_CREAT | FXF_EXCL,
            Disposition::Truncate => FXF_CREAT | FXF_TRUNC,
            Disposition::Resume => 0,
        };
    let mode = options.create_mode.map_or(DEFAULT_FILE_MODE, |m| m & MODE_BITS);
    let attrs = Attrs { permissions: Some(mode), ..Attrs::default() };
    let handle = match client.open(remote, flags, &attrs, cancel).await {
        Ok(handle) => handle,
        Err(f) => {
            let status = f.status(&display(remote));
            if matches!(status.name, ErrorName::ConnectionLost | ErrorName::Canceled | ErrorName::Timeout) {
                return Err(status);
            }
            return Err(match client.stat(remote, true, cancel).await.map(|a| entry_from(&a, b"").kind) {
                Ok(EntryType::Directory) => {
                    Status::new(ErrorName::IsADirectory, format!("{} is a folder", display(remote)))
                }
                Ok(_) if options.disposition == Disposition::CreateNew => {
                    Status::new(ErrorName::AlreadyExists, format!("{} exists", display(remote)))
                }
                _ => status,
            });
        }
    };
    if options.disposition != Disposition::Resume {
        return Ok(handle);
    }
    // The remote size must be the offset the caller continues at.
    let checked = match client.fstat(&handle, cancel).await {
        Ok(attrs) => {
            let size = attrs.size.unwrap_or(0);
            if size == options.resume_offset {
                Ok(handle.clone())
            } else {
                Err(Status::new(
                    ErrorName::ProtocolError,
                    format!("Cannot resume at {}: the file has {size} bytes", options.resume_offset),
                ))
            }
        }
        Err(f) => Err(f.status(&display(remote))),
    };
    if checked.is_err() {
        client.close_detached(&handle);
    }
    checked
}

/// Opens `remote` for reading; its size, refusing a folder.
///
/// # Errors
/// `IsADirectory`; as the server reports it.
pub async fn open_for_read(
    client: &Client,
    remote: &[u8],
    cancel: &CancelToken,
) -> Result<(Vec<u8>, Option<u64>), Status> {
    let handle = client
        .open(remote, FXF_READ, &Attrs::default(), cancel)
        .await
        .map_err(|f| f.status(&display(remote)))?;
    match client.fstat(&handle, cancel).await {
        Ok(attrs) if entry_from(&attrs, b"").kind == EntryType::Directory => {
            client.close_detached(&handle);
            Err(Status::new(ErrorName::IsADirectory, format!("{} is a folder", display(remote))))
        }
        Ok(attrs) => Ok((handle, attrs.size)),
        Err(Failure::Local(s)) => {
            client.close_detached(&handle);
            Err(s)
        }
        // A server that cannot FSTAT the handle still reads it.
        Err(Failure::Server(_)) => Ok((handle, None)),
    }
}

/// Fills `buf` from `source`; less only at its end.
fn read_fully(source: &mut dyn Source, buf: &mut [u8]) -> Result<usize, Status> {
    let mut done = 0;
    while let Some(rest) = buf.get_mut(done..)
        && !rest.is_empty()
    {
        let n = source.read(rest)?;
        if n == 0 {
            break;
        }
        done = done.saturating_add(n.min(rest.len()));
    }
    Ok(done)
}

/// An upload: pipelined WRITEs, then fsync when offered, CLOSE and the modification time.
#[derive(Debug)]
pub struct Upload<'a> {
    /// The client.
    pub client: &'a Client,
    /// The extensions offered.
    pub ext: &'a Extensions,
    /// WRITE length.
    pub chunk: u32,
}

impl Upload<'_> {
    /// Streams `source` to `remote`.
    ///
    /// # Errors
    /// `Canceled`; the source's failure; `NoSpace`; as the server reports it.
    pub async fn run(
        &self,
        remote: &[u8],
        options: &WriteOptions,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        stopped(cancel, progress)?;
        let handle = open_for_write(self.client, remote, options, cancel).await?;
        let base = if options.disposition == Disposition::Resume { options.resume_offset } else { 0 };
        let total = source.size().and_then(|s| s.checked_add(base));
        let result = self.write_all(&handle, remote, base, total, source, progress, cancel).await;
        if let Err(e) = result {
            self.client.close_detached(&handle);
            return Err(e);
        }
        if let Err(f) = self.client.close(&handle, cancel).await {
            return Err(write_failure(self.client, self.ext, remote, &f, 1, cancel).await);
        }
        if let Some(mtime) = options.mtime_ms {
            set_times(self.client, remote, Some(mtime), None, None, cancel).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, reason = "the parts of one transfer")]
    async fn write_all(
        &self,
        handle: &[u8],
        remote: &[u8],
        base: u64,
        total: Option<u64>,
        source: &mut dyn Source,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let mut buf = vec![0; usize::try_from(self.chunk).unwrap_or(usize::MAX)];
        let mut queue: VecDeque<(u64, Pending)> = VecDeque::new();
        let mut offset = base;
        let mut done = base;
        let mut eof = false;
        loop {
            stopped(cancel, progress)?;
            while !eof && queue.len() < WINDOW {
                let n = read_fully(source, &mut buf)?;
                eof = n < buf.len();
                let data = buf.get(..n).unwrap_or_default();
                if data.is_empty() {
                    break;
                }
                let pending =
                    self.client.write(handle, offset, data).map_err(|f| f.status(&display(remote)))?;
                queue.push_back((len_u64(n), pending));
                offset = offset.saturating_add(len_u64(n));
            }
            let Some((len, pending)) = queue.pop_front() else {
                break;
            };
            if let Err(f) = pending.wait(cancel).await.and_then(ok) {
                return Err(write_failure(self.client, self.ext, remote, &f, len, cancel).await);
            }
            done = done.saturating_add(len);
            progress.update(done, total);
        }
        if self.ext.fsync {
            let fsynced = match self.client.extended("fsync@openssh.com", &[Field::Str(handle)], cancel).await
            {
                Ok(reply) => ok(reply),
                Err(f) => Err(f),
            };
            if let Err(f) = fsynced {
                return Err(write_failure(self.client, self.ext, remote, &f, 1, cancel).await);
            }
        }
        Ok(())
    }
}

/// A download: pipelined READs into the sink.
#[derive(Debug)]
pub struct Download<'a> {
    /// The client.
    pub client: &'a Client,
    /// READ length.
    pub chunk: u32,
}

impl Download<'_> {
    /// `length` bytes (`None`: to the end) of `remote` from `offset`.
    ///
    /// # Errors
    /// `Canceled`; the sink's failure; `IsADirectory`; as the server
    /// reports it.
    pub async fn run(
        &self,
        remote: &[u8],
        offset: u64,
        length: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        stopped(cancel, progress)?;
        let end = match length {
            None => u64::MAX,
            Some(len) => offset.checked_add(len).ok_or_else(invalid_range)?,
        };
        let (handle, size) = open_for_read(self.client, remote, cancel).await?;
        let mut total = size.map(|s| s.saturating_sub(offset));
        if let Some(len) = length {
            total = Some(total.map_or(len, |t| t.min(len)));
        }
        let span = Span { start: offset, end, size };
        let result = self.read_all(&handle, remote, span, total, sink, progress, cancel).await;
        if result.is_ok() {
            // Everything arrived; a failed CLOSE of a read changes nothing.
            drop(self.client.close(&handle, cancel).await);
        } else {
            self.client.close_detached(&handle);
        }
        result
    }

    #[allow(clippy::too_many_arguments, reason = "the parts of one transfer")]
    async fn read_all(
        &self,
        handle: &[u8],
        remote: &[u8],
        span: Span,
        total: Option<u64>,
        sink: &mut dyn Sink,
        progress: &mut dyn Progress,
        cancel: &CancelToken,
    ) -> Result<(), Status> {
        let Span { start, end, size } = span;
        let mut queue: VecDeque<(u64, u32, Pending)> = VecDeque::new();
        let mut next = start;
        let mut done = 0u64;
        // Requests go out up to the size the file had when it was opened;
        // beyond, one at a time finds the end, until data shows that the
        // file grew.
        let mut expected_end = size.map_or(end, |s| s.clamp(start, end));
        loop {
            stopped(cancel, progress)?;
            while queue.len() < WINDOW && next < end && (next < expected_end || queue.is_empty()) {
                let len =
                    u32::try_from(end.saturating_sub(next).min(u64::from(self.chunk))).unwrap_or(self.chunk);
                let pending = self.client.read(handle, next, len).map_err(|f| f.status(&display(remote)))?;
                queue.push_back((next, len, pending));
                next = next.saturating_add(u64::from(len));
            }
            let Some((at, len, pending)) = queue.pop_front() else {
                return Ok(());
            };
            let data = pending
                .wait(cancel)
                .await
                .and_then(|r| data_of(r, len))
                .map_err(|f| f.status(&display(remote)))?;
            // The end of the file; the answers still due are dropped.
            let Some(data) = data else {
                return Ok(());
            };
            sink.write(&data)?;
            let n = len_u64(data.len());
            done = done.saturating_add(n);
            progress.update(done, total);
            let reached = at.saturating_add(n);
            if reached > expected_end {
                expected_end = end;
            }
            if n < u64::from(len) {
                // A short answer: the rest of its block is asked for before
                // the requests behind it are taken.
                let rest = u32::try_from(u64::from(len).saturating_sub(n)).unwrap_or(len);
                let pending =
                    self.client.read(handle, reached, rest).map_err(|f| f.status(&display(remote)))?;
                queue.push_front((reached, rest, pending));
            }
        }
    }
}

/// The bytes a download asks for, and the size of the file at open.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
    size: Option<u64>,
}

/// One request of a read handle on its way.
#[derive(Debug)]
struct InFlight {
    offset: u64,
    len: u32,
    pending: Pending,
}

/// One open file read at any offset. Reads are served from requests already on their way when access is
/// sequential or `read_ahead` asked for them; surplus bytes are kept for the next read.
#[derive(Debug)]
pub struct SftpRead {
    client: Client,
    handle: Vec<u8>,
    remote: Vec<u8>,
    size: Option<u64>,
    chunk: u32,
    /// Requests in flight at most.
    window: usize,
    /// Contiguous, oldest first, ending at `next`.
    pending: VecDeque<InFlight>,
    /// Offset of the next request.
    next: u64,
    /// Received and not handed out: `[buffer_at, +len)`.
    buffer: Vec<u8>,
    buffer_at: u64,
    /// End of the previous read, for sequential access.
    last_end: u64,
    /// Automatic read-ahead beyond a sequential read.
    ahead: u64,
    /// `read_ahead`: requests wanted for `[hint.0, hint.1)`.
    hint: (u64, u64),
}

impl SftpRead {
    /// A handle on `handle` of `remote`.
    #[must_use]
    pub fn new(client: Client, handle: Vec<u8>, remote: Vec<u8>, size: Option<u64>, chunk: u32) -> Self {
        let per = u64::from(chunk.max(1));
        let window =
            usize::try_from(MAX_READ_AHEAD.checked_div(per).unwrap_or(1)).unwrap_or(WINDOW).clamp(1, WINDOW);
        Self {
            client,
            handle,
            remote,
            size,
            chunk: chunk.max(1),
            window,
            pending: VecDeque::new(),
            next: 0,
            buffer: Vec::new(),
            buffer_at: 0,
            last_end: 0,
            ahead: 0,
            hint: (0, 0),
        }
    }

    fn span(&self) -> u64 {
        u64::try_from(self.window).unwrap_or(1).saturating_mul(u64::from(self.chunk))
    }

    fn buffer_end(&self) -> u64 {
        self.buffer_at.saturating_add(len_u64(self.buffer.len()))
    }

    /// Requests for other offsets are dropped (their answers when they come).
    fn restart_at(&mut self, offset: u64) {
        self.pending.clear();
        self.next = offset;
    }

    /// Sends requests up to `until`, at most `window` in flight.
    fn issue(&mut self, until: u64) -> Result<(), Failure> {
        while self.pending.len() < self.window && self.next < until {
            let len = u32::try_from(until.saturating_sub(self.next).min(u64::from(self.chunk)))
                .unwrap_or(self.chunk);
            let pending = self.client.read(&self.handle, self.next, len)?;
            self.pending.push_back(InFlight { offset: self.next, len, pending });
            self.next = self.next.saturating_add(u64::from(len));
        }
        Ok(())
    }

    /// Sequential reads grow the automatic read-ahead up to the window; a
    /// jump ends it.
    fn plan(&mut self, offset: u64, end: u64) {
        self.ahead = if offset == self.last_end && offset > 0 {
            self.ahead.saturating_mul(2).max(u64::from(self.chunk)).min(self.span())
        } else {
            0
        };
        self.last_end = end;
    }

    /// Copies what the kept data has of `[position, end)` into `out`.
    fn take_buffered(&mut self, position: &mut u64, out: &mut [u8], filled: &mut usize) {
        let buffer_end = self.buffer_end();
        if self.buffer.is_empty() || *position < self.buffer_at || *position >= buffer_end {
            self.buffer.clear();
            return;
        }
        let skip = usize::try_from(position.saturating_sub(self.buffer_at)).unwrap_or(usize::MAX);
        let available = self.buffer.get(skip..).unwrap_or_default();
        let room = out.get_mut(*filled..).unwrap_or_default();
        let n = available.len().min(room.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..n), available.get(..n)) {
            dst.copy_from_slice(src);
        }
        *filled = filled.saturating_add(n);
        *position = position.saturating_add(len_u64(n));
        if *position >= buffer_end {
            self.buffer.clear();
        }
    }

    /// Waits for the oldest request; hands out what fits, keeps the rest.
    /// `false` at the end of the file.
    async fn receive(
        &mut self,
        position: &mut u64,
        out: &mut [u8],
        filled: &mut usize,
        cancel: &CancelToken,
    ) -> Result<bool, Status> {
        let Some(InFlight { offset, len, pending }) = self.pending.pop_front() else {
            return Ok(false);
        };
        let data = match pending.wait(cancel).await.and_then(|r| data_of(r, len)) {
            Ok(data) => data,
            Err(f) => {
                self.restart_at(*position);
                return Err(f.status(&display(&self.remote)));
            }
        };
        let Some(data) = data else {
            self.restart_at(*position);
            return Ok(false);
        };
        let room = out.get_mut(*filled..).unwrap_or_default();
        let used = data.len().min(room.len());
        if let (Some(dst), Some(src)) = (room.get_mut(..used), data.get(..used)) {
            dst.copy_from_slice(src);
        }
        *filled = filled.saturating_add(used);
        *position = position.saturating_add(len_u64(used));
        // What did not fit is kept (the kept data was used up before).
        self.buffer = data.get(used..).unwrap_or_default().to_vec();
        self.buffer_at = *position;
        // A short answer: the rest of its block is asked for before the
        // requests behind it are taken.
        let n = len_u64(data.len());
        if n < u64::from(len) {
            let at = offset.saturating_add(n);
            let rest = u32::try_from(u64::from(len).saturating_sub(n)).unwrap_or(len);
            match self.client.read(&self.handle, at, rest) {
                Ok(pending) => self.pending.push_front(InFlight { offset: at, len: rest, pending }),
                Err(f) => {
                    self.restart_at(*position);
                    return Err(f.status(&display(&self.remote)));
                }
            }
        }
        Ok(true)
    }
}

impl ReadHandle for SftpRead {
    fn size(&self) -> Option<u64> {
        self.size
    }

    async fn read(&mut self, offset: u64, buf: &mut [u8], cancel: &CancelToken) -> Result<usize, Status> {
        if self.client.is_ended() {
            return Err(self.client.end_reason());
        }
        cancel.check()?;
        let end = offset.checked_add(len_u64(buf.len())).ok_or_else(invalid_range)?;
        if buf.is_empty() {
            return Ok(0);
        }
        let mut position = offset;
        let mut filled = 0;
        self.plan(position, end);
        self.take_buffered(&mut position, buf, &mut filled);
        // Requests already on their way for other offsets are dropped (a
        // read the kept data answered completely leaves them alone).
        if position < end && self.pending.front().is_some_and(|p| p.offset != position) {
            self.restart_at(position);
        }
        if self.pending.is_empty() {
            self.next = position;
        }
        while position < end {
            cancel.check()?;
            // A hint that starts by the end of this read carries it on to
            // the hint's end (one that ends before adds nothing).
            let hinted = self.hint.0 <= end;
            let wanted = end.saturating_add(self.ahead).max(if hinted { self.hint.1 } else { end });
            // Nothing is read ahead beyond the size the file had at open.
            let known = self.size.map_or(u64::MAX, |s| s.max(end));
            self.issue(wanted.min(end.saturating_add(self.span())).min(known))
                .map_err(|f| f.status(&display(&self.remote)))?;
            if !self.receive(&mut position, buf, &mut filled, cancel).await? {
                break;
            }
        }
        Ok(filled)
    }

    fn read_ahead(&mut self, offset: u64, bytes: u64) {
        // A hint: requests go out now when they continue what is asked for
        // already (or nothing is); otherwise it is ignored. Errors show at
        // the next read.
        let start = offset;
        // Nothing is read ahead beyond the size the file had at open.
        let until = start.saturating_add(bytes.min(MAX_READ_AHEAD)).min(self.size.unwrap_or(u64::MAX));
        if self.client.is_ended() || until <= start {
            return;
        }
        if let Some(front) = self.pending.front() {
            if start < front.offset || start > self.next {
                return;
            }
        } else if self.buffer.is_empty() || start < self.buffer_at || start > self.buffer_end() {
            self.buffer.clear();
            self.next = start;
        } else {
            self.next = self.buffer_end();
        }
        self.hint = (start, until);
        drop(self.issue(until));
    }

    async fn close(mut self, cancel: &CancelToken) -> Result<(), Status> {
        self.pending.clear();
        if self.client.is_ended() {
            return Err(self.client.end_reason());
        }
        match self.client.close(&self.handle, cancel).await {
            Ok(()) => Ok(()),
            Err(f) => Err(f.status(&display(&self.remote))),
        }
    }
}

/// Sequential, pipelined writes with an explicit commit.
#[derive(Debug)]
pub struct SftpWrite {
    client: Client,
    ext: Extensions,
    handle: Vec<u8>,
    remote: Vec<u8>,
    position: u64,
    chunk: u32,
    mtime_ms: Option<i64>,
    pending: VecDeque<(u64, Pending)>,
    /// The first failure; every later call returns it.
    failure: Option<Status>,
}

impl SftpWrite {
    /// A handle on `handle` of `remote`, writing at `position`.
    #[must_use]
    pub fn new(
        client: Client,
        ext: Extensions,
        handle: Vec<u8>,
        remote: Vec<u8>,
        options: &WriteOptions,
        chunk: u32,
    ) -> Self {
        let position = if options.disposition == Disposition::Resume { options.resume_offset } else { 0 };
        Self {
            client,
            ext,
            handle,
            remote,
            position,
            chunk: chunk.max(1),
            mtime_ms: options.mtime_ms,
            pending: VecDeque::new(),
            failure: None,
        }
    }

    fn usable(&self) -> Result<(), Status> {
        if let Some(f) = &self.failure {
            return Err(f.clone());
        }
        if self.client.is_ended() {
            return Err(self.client.end_reason());
        }
        Ok(())
    }

    /// Waits for the oldest WRITE; a failure sticks.
    async fn settle_oldest(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        let Some((len, pending)) = self.pending.pop_front() else {
            return Ok(());
        };
        if let Err(f) = pending.wait(cancel).await.and_then(ok) {
            // A canceled wait leaves the fate of that block unknown: the
            // handle stays failed (resume from the remote size instead).
            let status = write_failure(&self.client, &self.ext, &self.remote, &f, len, cancel).await;
            self.failure = Some(status.clone());
            return Err(status);
        }
        Ok(())
    }

    /// Every WRITE acknowledged, then fsync when offered.
    async fn finish(&mut self, cancel: &CancelToken) -> Result<(), Status> {
        self.usable()?;
        while !self.pending.is_empty() {
            self.settle_oldest(cancel).await?;
        }
        if self.ext.fsync {
            let fsynced =
                match self.client.extended("fsync@openssh.com", &[Field::Str(&self.handle)], cancel).await {
                    Ok(reply) => ok(reply),
                    Err(f) => Err(f),
                };
            if let Err(f) = fsynced {
                return Err(write_failure(&self.client, &self.ext, &self.remote, &f, 1, cancel).await);
            }
        }
        Ok(())
    }
}

impl WriteHandle for SftpWrite {
    async fn write(&mut self, data: &[u8], cancel: &CancelToken) -> Result<(), Status> {
        self.usable()?;
        let chunk = usize::try_from(self.chunk).unwrap_or(usize::MAX);
        for piece in data.chunks(chunk) {
            cancel.check()?;
            if self.pending.len() >= WINDOW {
                self.settle_oldest(cancel).await?;
            }
            match self.client.write(&self.handle, self.position, piece) {
                Ok(pending) => self.pending.push_back((len_u64(piece.len()), pending)),
                Err(f) => {
                    let status = f.status(&display(&self.remote));
                    self.failure = Some(status.clone());
                    return Err(status);
                }
            }
            self.position = self.position.saturating_add(len_u64(piece.len()));
        }
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }

    async fn commit(mut self, cancel: &CancelToken) -> Result<(), Status> {
        if let Err(e) = self.finish(cancel).await {
            self.pending.clear();
            self.client.close_detached(&self.handle);
            return Err(e);
        }
        if let Err(f) = self.client.close(&self.handle, cancel).await {
            return Err(write_failure(&self.client, &self.ext, &self.remote, &f, 1, cancel).await);
        }
        // The modification time is applied on commit.
        if let Some(mtime) = self.mtime_ms {
            set_times(&self.client, &self.remote, Some(mtime), None, None, cancel).await?;
        }
        Ok(())
    }

    fn abort(mut self) -> impl Future<Output = ()> {
        self.pending.clear();
        self.client.close_detached(&self.handle);
        std::future::ready(())
    }
}

#[cfg(test)]
mod tests;
