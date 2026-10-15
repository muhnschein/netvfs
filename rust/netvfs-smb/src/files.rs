// SPDX-License-Identifier: LGPL-2.1-or-later
//! Read and write handles (XC-13, XM-6): READ and WRITE requests in
//! chunks of min(MaxReadSize/MaxWriteSize, 1 MiB) (M-11), up to
//! [`MAX_IN_FLIGHT`] bytes on the way per handle (C-10).

use std::collections::VecDeque;
use std::sync::Arc;

use netvfs_vfs::{CancelToken, ErrorName, ReadHandle, Status, WriteHandle};

use crate::conn::{Conn, Element, Target, Ticket};
use crate::error::{Error, Phase, Result};
use crate::fs;
use crate::msg::Command;
use crate::msg::file::{
    self, FileId, check_close_response, check_flush_response, close_request, filetime_of_ms, flush_request,
};
use crate::session::Tree;
use crate::status::NtStatus;

/// Bytes requested ahead and not yet handed out, per handle (XM-6).
pub const MAX_IN_FLIGHT: usize = 4 * 1024 * 1024;
/// The largest chunk (M-11).
pub const MAX_CHUNK: usize = 1024 * 1024;

/// The chunk for a server maximum (M-11); one credit's worth without
/// multi-credit requests.
#[must_use]
pub fn chunk(server_max: usize, multi_credit: bool) -> usize {
    let limit = if multi_credit { MAX_CHUNK } else { crate::conn::CREDIT_UNIT };
    server_max.min(limit).max(1)
}

/// An open file of a tree.
#[derive(Debug)]
pub struct Open {
    /// The connection.
    pub conn: Conn,
    /// The tree; held so that it is not disconnected while the file is
    /// open.
    pub tree: Arc<Tree>,
    /// The handle.
    pub file_id: FileId,
}

impl Open {
    fn target(&self) -> Target {
        self.tree.target()
    }

    /// CLOSE, waited for.
    async fn close(&self, cancel: &CancelToken) -> Result<()> {
        let resp = self
            .conn
            .call(self.target(), Element::new(Command::Close, close_request(&self.file_id)), cancel)
            .await;
        if matches!(resp, Err(Error::Canceled)) {
            // A canceled call still closes the file, without waiting.
            self.conn.close_detached(self.target(), &self.file_id);
        }
        let resp = resp?;
        resp.ok()?;
        check_close_response(&resp.msg)
    }
}

fn status(e: Error, context: &str) -> Status {
    e.status(context, Phase::Established)
}

/// One READ on the way or answered.
#[derive(Debug)]
struct Chunk {
    offset: u64,
    count: usize,
    ticket: Option<Ticket>,
    data: Vec<u8>,
    used: usize,
}

impl Chunk {
    /// Bytes requested and not yet handed out.
    fn left(&self) -> usize {
        if self.ticket.is_some() { self.count } else { self.data.len().saturating_sub(self.used) }
    }

    /// Where the next byte handed out comes from.
    fn next(&self) -> u64 {
        self.offset.saturating_add(u64::try_from(self.used).unwrap_or(u64::MAX))
    }
}

/// [`ReadHandle`] of SMB.
#[derive(Debug)]
pub struct SmbRead {
    open: Option<Open>,
    size: u64,
    chunk: usize,
    queue: VecDeque<Chunk>,
}

impl SmbRead {
    /// A handle on `open`, a file of `size` bytes.
    #[must_use]
    pub fn new(open: Open, size: u64, chunk: usize) -> Self {
        Self { open: Some(open), size, chunk, queue: VecDeque::new() }
    }

    fn open(&self) -> Result<&Open> {
        let open = self.open.as_ref().ok_or_else(|| Error::Local(Status::internal("the file is closed")))?;
        open.conn.usable()?;
        Ok(open)
    }

    /// Where the queue ends.
    fn queue_end(&self) -> Option<u64> {
        self.queue.back().map(|c| c.offset.saturating_add(u64::try_from(c.count).unwrap_or(u64::MAX)))
    }

    fn queued(&self) -> usize {
        self.queue.iter().map(Chunk::left).sum()
    }

    /// Drops the queue; outstanding READs are canceled.
    fn discard(&mut self) {
        self.queue.clear();
    }

    /// The next READ of [`Self::fill`]: offset and length, if one is due.
    fn due(&self, from: u64, to: u64) -> Option<(u64, usize)> {
        let next = self.queue_end().unwrap_or(from);
        let room = self.queue.is_empty() || self.queued().saturating_add(self.chunk) <= MAX_IN_FLIGHT;
        if next >= to || !room {
            return None;
        }
        let count = usize::try_from(to.saturating_sub(next)).unwrap_or(usize::MAX).min(self.chunk);
        Some((next, count))
    }

    fn request(&self, offset: u64, count: usize) -> Result<Element> {
        let open = self.open()?;
        Ok(Element::new(Command::Read, file::read_request(&open.file_id, offset, count)?).payload(count))
    }

    fn push(&mut self, offset: u64, count: usize, ticket: Ticket) {
        self.queue.push_back(Chunk { offset, count, ticket: Some(ticket), data: Vec::new(), used: 0 });
    }

    /// READs for `from..to` until the window is full, waiting for credits.
    async fn fill(&mut self, from: u64, to: u64, cancel: &CancelToken) -> Result<()> {
        while let Some((offset, count)) = self.due(from, to) {
            let element = self.request(offset, count)?;
            let open = self.open()?;
            let ticket = open.conn.send(open.target(), vec![element], cancel).await?.pop();
            self.push(offset, count, ticket.ok_or_else(|| crate::error::protocol("no ticket"))?);
        }
        Ok(())
    }

    /// Hands out what the front chunk has for `buf`; `true` at the end of
    /// the file.
    async fn consume(&mut self, buf: &mut [u8], cancel: &CancelToken) -> Result<(usize, bool)> {
        let front = self.queue.front_mut().ok_or_else(|| crate::error::protocol("no read queued"))?;
        if let Some(ticket) = front.ticket.take() {
            let resp = ticket.wait(cancel).await?;
            if resp.expect(&[NtStatus::END_OF_FILE])? == NtStatus::SUCCESS {
                front.data = file::read_response(&resp.msg, front.count)?.to_vec();
            }
        }
        let available = front.data.get(front.used..).unwrap_or_default();
        let take = available.len().min(buf.len());
        let (dst, src) = (buf.get_mut(..take).unwrap_or_default(), available.get(..take).unwrap_or_default());
        dst.copy_from_slice(src);
        front.used = front.used.saturating_add(take);
        if front.used < front.data.len() {
            return Ok((take, false));
        }
        // A short read is the end of the file; what was asked beyond is moot.
        let eof = front.data.len() < front.count;
        self.queue.pop_front();
        if eof {
            self.discard();
        }
        Ok((take, eof))
    }

    async fn read_inner(&mut self, offset: u64, buf: &mut [u8], cancel: &CancelToken) -> Result<usize> {
        self.open()?;
        // C-9: also when what is asked for has arrived already.
        if cancel.is_canceled() {
            return Err(Error::Canceled);
        }
        if self.queue.front().is_some_and(|c| c.next() != offset) {
            self.discard(); // not where the queue continues: a new position
        }
        let end = offset.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        let mut filled = 0usize;
        while filled < buf.len() {
            let at = offset.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
            // Up to the size at open time in parallel; past it one chunk at
            // a time, in case the file grew.
            let to = if at < self.size {
                end.min(self.size)
            } else {
                end.min(at.saturating_add(u64::try_from(self.chunk).unwrap_or(u64::MAX)))
            };
            self.fill(at, to, cancel).await?;
            let (n, eof) = self.consume(buf.get_mut(filled..).unwrap_or_default(), cancel).await?;
            filled = filled.saturating_add(n);
            if eof {
                break;
            }
        }
        Ok(filled)
    }
}

impl ReadHandle for SmbRead {
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }

    async fn read(
        &mut self,
        offset: u64,
        buf: &mut [u8],
        cancel: &CancelToken,
    ) -> std::result::Result<usize, Status> {
        if buf.is_empty() {
            return self.open().map(|_| 0).map_err(|e| status(e, "read"));
        }
        let r = self.read_inner(offset, buf, cancel).await;
        if r.is_err() {
            self.discard();
        }
        r.map_err(|e| status(e, "read"))
    }

    fn read_ahead(&mut self, offset: u64, bytes: u64) {
        if self.open().is_err() || bytes == 0 {
            return;
        }
        let front = self.queue.front().map(Chunk::next);
        if front.is_some_and(|f| offset < f) || self.queue_end().is_some_and(|e| offset > e) {
            self.discard();
        }
        let window = u64::try_from(MAX_IN_FLIGHT).unwrap_or(u64::MAX);
        let to = offset.saturating_add(bytes.min(window)).min(self.size.max(offset));
        // A hint: a request that cannot go now is simply not made.
        while let Some((at, count)) = self.due(offset, to) {
            let Ok(element) = self.request(at, count) else { return };
            let Some(open) = self.open.as_ref() else { return };
            match open.conn.send_now(open.target(), &[element]) {
                Ok(Some(mut tickets)) => match tickets.pop() {
                    Some(ticket) => self.push(at, count, ticket),
                    None => return,
                },
                Ok(None) | Err(_) => return,
            }
        }
    }

    async fn close(mut self, cancel: &CancelToken) -> std::result::Result<(), Status> {
        self.discard();
        let open = self.open.take().ok_or_else(|| Status::internal("the file is closed"))?;
        open.close(cancel).await.map_err(|e| status(e, "close"))
    }
}

impl Drop for SmbRead {
    fn drop(&mut self) {
        self.discard();
        if let Some(open) = self.open.take() {
            open.conn.close_detached(open.target(), &open.file_id);
        }
    }
}

/// One WRITE on the way.
#[derive(Debug)]
struct InFlight {
    offset: u64,
    data: Vec<u8>,
    ticket: Ticket,
}

/// [`WriteHandle`] of SMB.
#[derive(Debug)]
pub struct SmbWrite {
    open: Option<Open>,
    /// The file's path, for the modification time after the close.
    path: Vec<u16>,
    mtime_ms: Option<i64>,
    chunk: usize,
    position: u64,
    sent: u64,
    buffer: Vec<u8>,
    in_flight: VecDeque<InFlight>,
    in_flight_bytes: usize,
    /// A failed write leaves the file in an unknown state: later writes and
    /// commit report the same failure.
    failed: Option<Status>,
}

impl SmbWrite {
    /// A handle on `open` at `position` (Resume: the file's size).
    #[must_use]
    pub fn new(open: Open, path: Vec<u16>, position: u64, mtime_ms: Option<i64>, chunk: usize) -> Self {
        Self {
            open: Some(open),
            path,
            mtime_ms,
            chunk,
            position,
            sent: position,
            buffer: Vec::new(),
            in_flight: VecDeque::new(),
            in_flight_bytes: 0,
            failed: None,
        }
    }

    fn open(&self) -> std::result::Result<&Open, Status> {
        if let Some(failed) = &self.failed {
            return Err(failed.clone());
        }
        let open = self.open.as_ref().ok_or_else(|| Status::internal("the file is closed"))?;
        open.conn.usable().map_err(|e| status(e, "write"))?;
        Ok(open)
    }

    fn drop_in_flight(&mut self) {
        self.in_flight.clear();
        self.in_flight_bytes = 0;
        self.buffer.clear();
    }

    fn fail(&mut self, s: Status) -> Status {
        self.failed = Some(s.clone());
        self.drop_in_flight();
        s
    }

    /// Sends the buffer as one WRITE, after retiring what the window needs.
    async fn send(&mut self, cancel: &CancelToken) -> Result<()> {
        let count = self.buffer.len();
        while !self.in_flight.is_empty() && self.in_flight_bytes.saturating_add(count) > MAX_IN_FLIGHT {
            self.retire_oldest(cancel).await?;
        }
        let data = std::mem::take(&mut self.buffer);
        let open = self.open.as_ref().ok_or_else(|| Error::Local(Status::internal("the file is closed")))?;
        let element = Element::new(Command::Write, file::write_request(&open.file_id, self.sent, &data)?)
            .payload(count);
        let ticket = open.conn.send(open.target(), vec![element], cancel).await?.pop();
        let ticket = ticket.ok_or_else(|| crate::error::protocol("no ticket"))?;
        self.in_flight.push_back(InFlight { offset: self.sent, data, ticket });
        self.sent = self.sent.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        self.in_flight_bytes = self.in_flight_bytes.saturating_add(count);
        Ok(())
    }

    async fn retire_oldest(&mut self, cancel: &CancelToken) -> Result<()> {
        let Some(w) = self.in_flight.pop_front() else { return Ok(()) };
        self.in_flight_bytes = self.in_flight_bytes.saturating_sub(w.data.len());
        let resp = w.ticket.wait(cancel).await?;
        resp.ok()?;
        let written = file::write_response(&resp.msg, w.data.len())?;
        self.write_rest(&w.data, written, w.offset, cancel).await
    }

    /// After a short write the rest goes one request at a time, in order.
    async fn write_rest(
        &self,
        data: &[u8],
        mut done: usize,
        offset: u64,
        cancel: &CancelToken,
    ) -> Result<()> {
        if done == 0 {
            return Err(Error::Local(Status::new(
                ErrorName::ProtocolError,
                "write: the server accepted no data",
            )));
        }
        while let Some(rest) = data.get(done..).filter(|r| !r.is_empty()) {
            let open =
                self.open.as_ref().ok_or_else(|| Error::Local(Status::internal("the file is closed")))?;
            let at = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            let element = Element::new(Command::Write, file::write_request(&open.file_id, at, rest)?)
                .payload(rest.len());
            let resp = open.conn.call(open.target(), element, cancel).await?;
            resp.ok()?;
            let n = file::write_response(&resp.msg, rest.len())?;
            if n == 0 {
                return Err(Error::Local(Status::new(
                    ErrorName::ProtocolError,
                    "write: the server accepted no data",
                )));
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }

    async fn write_inner(&mut self, data: &[u8], cancel: &CancelToken) -> Result<()> {
        let mut done = 0usize;
        while let Some(rest) = data.get(done..).filter(|r| !r.is_empty()) {
            let take = self.chunk.saturating_sub(self.buffer.len()).min(rest.len());
            self.buffer.extend_from_slice(rest.get(..take).unwrap_or_default());
            done = done.saturating_add(take);
            if self.buffer.len() >= self.chunk {
                self.send(cancel).await?;
            }
        }
        Ok(())
    }

    /// Everything sent and answered, FLUSH (C-12: stable storage before
    /// the caller's size check and rename).
    async fn finish(&mut self, cancel: &CancelToken) -> Result<()> {
        if !self.buffer.is_empty() {
            self.send(cancel).await?;
        }
        while !self.in_flight.is_empty() {
            self.retire_oldest(cancel).await?;
        }
        let open = self.open.as_ref().ok_or_else(|| Error::Local(Status::internal("the file is closed")))?;
        let resp = open
            .conn
            .call(open.target(), Element::new(Command::Flush, flush_request(&open.file_id)), cancel)
            .await?;
        resp.ok()?;
        check_flush_response(&resp.msg)
    }
}

impl WriteHandle for SmbWrite {
    async fn write(&mut self, data: &[u8], cancel: &CancelToken) -> std::result::Result<(), Status> {
        self.open()?;
        if let Err(e) = self.write_inner(data, cancel).await {
            return Err(self.fail(status(e, "write")));
        }
        self.position = self.position.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }

    async fn commit(mut self, cancel: &CancelToken) -> std::result::Result<(), Status> {
        let mut r = self.open().map(drop);
        if r.is_ok() {
            r = self.finish(cancel).await.map_err(|e| status(e, "flush"));
        }
        self.drop_in_flight();
        let open = self.open.take().ok_or_else(|| Status::internal("the file is closed"))?;
        let closed = if r.is_ok() {
            open.close(cancel).await.map_err(|e| status(e, "close"))
        } else {
            open.conn.close_detached(open.target(), &open.file_id);
            Ok(())
        };
        r?;
        closed?;
        // XC-14: the time is set after the close, so that no later write
        // of this handle can move it again.
        if let Some(ft) = self.mtime_ms.and_then(filetime_of_ms) {
            fs::set_times(&open.conn, open.target(), &self.path, Some(ft), None, cancel)
                .await
                .map_err(|e| status(e, "set attributes"))?;
        }
        Ok(())
    }

    async fn abort(mut self) {
        self.drop_in_flight();
        if let Some(open) = self.open.take() {
            open.conn.close_detached(open.target(), &open.file_id);
        }
    }
}

impl Drop for SmbWrite {
    fn drop(&mut self) {
        self.drop_in_flight();
        if let Some(open) = self.open.take() {
            open.conn.close_detached(open.target(), &open.file_id);
        }
    }
}

#[cfg(test)]
mod tests;
