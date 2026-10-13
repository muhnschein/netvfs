// SPDX-License-Identifier: LGPL-2.1-or-later
//! The local side of `Upload` and `Download` (XB-11, port of `FdDevice`):
//! [`FdDevice`] reads and writes a checked descriptor for the C++
//! `CallbackDevice` (`nvb_io`), through [`ReadAt`] and [`WriteAt`].
//!
//! Regular files are random access within `[offset, offset + length)`,
//! mapped to device positions `[0, length)`, with `pread`/`pwrite`: the
//! consumer's file offset is neither used nor moved. FIFOs are sequential;
//! reads stop after `length` bytes when a length is given. Every wait for a
//! FIFO polls at most [`POLL_SLICE_MS`] at a time and gives up once the
//! cancel flag is set, so C-9 holds for local I/O too.

use super::fd::FdInfo;
use crate::ffi::{ReadAt, WriteAt};
use crate::sys::fd::{self, Ready};
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// The longest a FIFO wait goes without looking at the cancel flag.
pub const POLL_SLICE_MS: i32 = 200;
/// The most one call reads or writes (`INT_MAX`, as `FdDevice` did).
const MAX_CHUNK: usize = 0x7fff_ffff;

/// A checked descriptor as a transfer's local side. It borrows the
/// descriptor: the job owns it and closes it when the job ends.
#[derive(Debug)]
pub struct FdDevice<'a> {
    fd: BorrowedFd<'a>,
    info: FdInfo,
    offset: i64,
    length: i64,
    stream_pos: i64,
    transferred: i64,
    cancel: &'a AtomicBool,
}

impl<'a> FdDevice<'a> {
    /// A device over `fd` (checked with
    /// [`check_transfer_fd`](super::fd::check_transfer_fd), which gave
    /// `info`): from `offset` of a regular file (ignored for a FIFO), at
    /// most `length` bytes (-1: no limit).
    #[must_use]
    pub const fn new(
        fd: BorrowedFd<'a>,
        info: FdInfo,
        offset: i64,
        length: i64,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self { fd, info, offset, length, stream_pos: 0, transferred: 0, cancel }
    }

    /// A FIFO: no positions.
    #[must_use]
    pub const fn is_sequential(&self) -> bool {
        self.info.fifo
    }

    /// The bytes in range (`QIODevice::size`): the length when one is
    /// given, 0 for a FIFO, else what the file has after the offset now.
    #[must_use]
    pub fn size(&self) -> i64 {
        if self.length >= 0 {
            return self.length;
        }
        if self.info.fifo {
            return 0;
        }
        fd::stat(std::os::fd::AsRawFd::as_raw_fd(&self.fd))
            .map_or(0, |st| st.size.saturating_sub(self.offset).max(0))
    }

    /// Bytes read or written so far.
    #[must_use]
    pub const fn transferred(&self) -> i64 {
        self.transferred
    }

    fn canceled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    /// Waits until the FIFO is ready; false when canceled or on an error.
    fn wait_for(&self, ready: Ready) -> bool {
        loop {
            if self.canceled() {
                return false;
            }
            match fd::poll(self.fd, ready, POLL_SLICE_MS) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(_) => return false,
            }
        }
    }

    /// Writes all of `data` to the FIFO, at most `PIPE_BUF` per poll so
    /// that a write never blocks beyond the slice. The backends take a
    /// short write as a failure (`write(n) != n`), so this goes on until
    /// everything is written; FdDevice wrote one piece per call, which
    /// failed downloads of more than `PIPE_BUF` per chunk into a pipe. A
    /// cancel or an error after some bytes reports those.
    fn write_fifo(&mut self, data: &[u8]) -> Option<usize> {
        let mut written = 0;
        while written < data.len() {
            if !self.wait_for(Ready::Write) {
                break;
            }
            let end = written.saturating_add(libc::PIPE_BUF).min(data.len());
            match fd::write(self.fd, data.get(written..end)?) {
                Ok(n) if n > 0 => written = written.saturating_add(self.moved(n)),
                _ => break,
            }
        }
        (written > 0 || data.is_empty()).then_some(written)
    }

    /// Counts `n` bytes moved.
    fn moved(&mut self, n: usize) -> usize {
        let bytes = i64::try_from(n).unwrap_or(i64::MAX);
        self.stream_pos = self.stream_pos.saturating_add(bytes);
        self.transferred = self.transferred.saturating_add(bytes);
        n
    }
}

impl ReadAt for FdDevice<'_> {
    fn read_at(&mut self, pos: i64, buf: &mut [u8]) -> Option<usize> {
        if self.canceled() {
            return None;
        }
        let position = if self.info.fifo { self.stream_pos } else { pos };
        let mut want = buf.len().min(MAX_CHUNK);
        if self.length >= 0 {
            let left = self.length.saturating_sub(position);
            if left <= 0 {
                return Some(0);
            }
            want = want.min(usize::try_from(left).unwrap_or(usize::MAX));
        }
        let buf = buf.get_mut(..want)?;
        if buf.is_empty() {
            return Some(0);
        }
        let n = if self.info.fifo {
            if !self.wait_for(Ready::Read) {
                return None;
            }
            fd::read(self.fd, buf)
        } else {
            fd::pread(self.fd, buf, self.offset.saturating_add(position))
        };
        n.ok().map(|n| self.moved(n))
    }
}

impl WriteAt for FdDevice<'_> {
    fn write_at(&mut self, pos: i64, data: &[u8]) -> Option<usize> {
        if self.canceled() {
            return None;
        }
        if self.info.fifo {
            return self.write_fifo(data);
        }
        let mut written = 0;
        while written < data.len() {
            let end = written.saturating_add(MAX_CHUNK).min(data.len());
            let at = self.offset.saturating_add(pos).saturating_add(i64::try_from(written).ok()?);
            match fd::pwrite(self.fd, data.get(written..end)?, at) {
                Ok(n) if n > 0 => written = written.saturating_add(n),
                _ if written > 0 => break,
                _ => return None,
            }
        }
        self.transferred = self.transferred.saturating_add(i64::try_from(written).ok()?);
        Some(written)
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use crate::jobs::fd::{FdAccess, check_transfer_fd};
    use crate::test_support::{TempDir, write_file};
    use std::fs::{File, OpenOptions};
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn pipe() -> (File, File) {
        let (r, w) = std::io::pipe().unwrap();
        (File::from(OwnedFd::from(r)), File::from(OwnedFd::from(w)))
    }

    fn fifo() -> FdInfo {
        FdInfo { fifo: true, size: -1 }
    }

    /// The port of `tst_BridgeUnits::fdDeviceOffsets`.
    #[test]
    fn offsets_and_fifo_cancel() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_file(&path, b"0123456789");
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(3)).unwrap(); // the consumer's offset must not matter
        let info = check_transfer_fd(file.as_raw_fd(), FdAccess::Read).unwrap();
        let canceled = AtomicBool::new(false);
        {
            let mut input = FdDevice::new(file.as_fd(), info, 4, 3, &canceled);
            assert!(!input.is_sequential());
            assert_eq!(input.size(), 3);
            let mut buf = [0u8; 16];
            assert_eq!(input.read_at(0, &mut buf), Some(3));
            assert_eq!(&buf[..3], b"456");
            assert_eq!(input.read_at(3, &mut buf), Some(0));
            assert_eq!(input.read_at(1, &mut buf[..1]), Some(1));
            assert_eq!(&buf[..1], b"5");
            assert_eq!(input.read_at(2, &mut buf), Some(1));
            assert_eq!(&buf[..1], b"6");
            assert_eq!(input.transferred(), 5);
        }
        {
            let mut out = FdDevice::new(file.as_fd(), info, 8, -1, &canceled);
            assert_eq!(out.write_at(0, b"ABCD"), Some(4));
            assert_eq!(out.transferred(), 4);
            // The size of a range without a length: what the file has after
            // the offset, now.
            assert_eq!(out.size(), 4);
            assert_eq!(out.write_at(2, b"x"), Some(1));
            assert_eq!(out.transferred(), 5);
            assert_eq!(out.write_at(0, b""), Some(0));
        }
        assert_eq!(file.stream_position().unwrap(), 3);
        drop(file); // the device does not own the descriptor
        assert_eq!(std::fs::read(&path).unwrap(), b"01234567ABxD");

        // A FIFO read gives up when canceled, without data arriving.
        let (r, _w) = pipe();
        let info = check_transfer_fd(r.as_raw_fd(), FdAccess::Read).unwrap();
        let canceled = Arc::new(AtomicBool::new(false));
        let mut device = FdDevice::new(r.as_fd(), info, 0, -1, &canceled);
        assert!(device.is_sequential());
        assert_eq!(device.size(), 0);
        let flag = Arc::clone(&canceled);
        let start = Instant::now();
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::Release);
        });
        let mut c = [0u8; 1];
        assert_eq!(device.read_at(0, &mut c), None);
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(90), "{waited:?}");
        assert!(waited < Duration::from_secs(1), "{waited:?}");
        setter.join().unwrap();
        // Canceled already: at once.
        let start = Instant::now();
        assert_eq!(device.read_at(0, &mut c), None);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn fifo_reads_stop_after_the_length() {
        let (r, mut w) = pipe();
        w.write_all(b"abcdef").unwrap();
        drop(w);
        let canceled = AtomicBool::new(false);
        let mut device = FdDevice::new(r.as_fd(), fifo(), 99, 4, &canceled);
        assert_eq!(device.size(), 4);
        let mut buf = [0u8; 3];
        // Positions are ignored for a FIFO.
        assert_eq!(device.read_at(77, &mut buf), Some(3));
        assert_eq!(&buf, b"abc");
        assert_eq!(device.read_at(0, &mut buf), Some(1));
        assert_eq!(&buf[..1], b"d");
        assert_eq!(device.read_at(0, &mut buf), Some(0));
        assert_eq!(device.transferred(), 4);
        // Without a length, to the end of the stream.
        let mut rest = FdDevice::new(r.as_fd(), fifo(), 0, -1, &canceled);
        assert_eq!(rest.read_at(0, &mut buf), Some(2));
        assert_eq!(&buf[..2], b"ef");
        assert_eq!(rest.read_at(0, &mut buf), Some(0));
        assert_eq!(rest.transferred(), 2);
        // An empty buffer reads nothing.
        assert_eq!(rest.read_at(0, &mut []), Some(0));
    }

    #[test]
    fn fifo_writes_a_pipe_buf_at_a_time() {
        let (mut r, w) = pipe();
        let canceled = AtomicBool::new(false);
        let mut device = FdDevice::new(w.as_fd(), fifo(), 5, -1, &canceled);
        let data = vec![7u8; libc::PIPE_BUF * 2 + 1];
        assert_eq!(device.write_at(0, &data), Some(data.len()));
        assert_eq!(device.write_at(0, b"xy"), Some(2));
        assert_eq!(device.write_at(0, b""), Some(0));
        assert_eq!(device.transferred(), i64::try_from(data.len() + 2).unwrap());
        drop(w);
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut got).unwrap();
        assert_eq!(got.len(), data.len() + 2);
        assert_eq!(&got[data.len()..], b"xy");
    }

    #[test]
    fn fifo_write_reports_what_went_before_a_cancel() {
        let (mut r, w) = pipe();
        // Fill the pipe, then free one page: one PIPE_BUF piece fits.
        let fill = vec![0u8; libc::PIPE_BUF];
        while fd::poll(w.as_fd(), Ready::Write, 0).unwrap() {
            assert_eq!(fd::write(w.as_fd(), &fill).unwrap(), libc::PIPE_BUF);
        }
        std::io::Read::read_exact(&mut r, &mut vec![0u8; libc::PIPE_BUF]).unwrap();
        let canceled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&canceled);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::Release);
        });
        let mut device = FdDevice::new(w.as_fd(), fifo(), 0, -1, &canceled);
        assert_eq!(device.write_at(0, &vec![1u8; libc::PIPE_BUF * 2]), Some(libc::PIPE_BUF));
        assert_eq!(device.transferred(), i64::try_from(libc::PIPE_BUF).unwrap());
        setter.join().unwrap();
    }

    #[test]
    fn fifo_write_gives_up_when_canceled_or_broken() {
        let (r, w) = pipe();
        // Fill the pipe so that the next write would block.
        let fill = vec![0u8; 1 << 20];
        let mut filled = 0;
        while fd::poll(w.as_fd(), Ready::Write, 0).unwrap() {
            filled += fd::write(w.as_fd(), &fill[..libc::PIPE_BUF]).unwrap();
        }
        assert!(filled > 0);
        let canceled = Arc::new(AtomicBool::new(false));
        let mut device = FdDevice::new(w.as_fd(), fifo(), 0, -1, &canceled);
        let flag = Arc::clone(&canceled);
        let start = Instant::now();
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::Release);
        });
        assert_eq!(device.write_at(0, b"x"), None);
        assert!(start.elapsed() >= Duration::from_millis(90));
        assert!(start.elapsed() < Duration::from_secs(1));
        setter.join().unwrap();
        // A canceled device writes nothing.
        assert_eq!(device.write_at(0, b"x"), None);
        // The reader is gone: the write fails.
        drop(r);
        let not_canceled = AtomicBool::new(false);
        let mut broken = FdDevice::new(w.as_fd(), fifo(), 0, -1, &not_canceled);
        assert_eq!(broken.write_at(0, b"x"), None);
        assert_eq!(broken.transferred(), 0);
    }

    #[test]
    fn regular_file_edges() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_file(&path, b"0123456789");
        let rw = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let info = FdInfo { fifo: false, size: 10 };
        let canceled = AtomicBool::new(false);
        // No length: to the end of the file.
        let mut all = FdDevice::new(rw.as_fd(), info, 6, -1, &canceled);
        assert_eq!(all.size(), 4);
        let mut buf = [0u8; 16];
        assert_eq!(all.read_at(0, &mut buf), Some(4));
        assert_eq!(&buf[..4], b"6789");
        assert_eq!(all.read_at(4, &mut buf), Some(0));
        // An offset past the end: nothing in range.
        let past = FdDevice::new(rw.as_fd(), info, 20, -1, &canceled);
        assert_eq!(past.size(), 0);
        // A position the file cannot have (negative): an error.
        assert_eq!(all.read_at(-7, &mut buf), None);
        assert_eq!(all.write_at(-7, b"x"), None);
        // A read-only descriptor cannot be written.
        let ro = File::open(&path).unwrap();
        let mut device = FdDevice::new(ro.as_fd(), info, 0, -1, &canceled);
        assert_eq!(device.write_at(0, b"x"), None);
        assert_eq!(device.transferred(), 0);
        // Canceled: nothing more is read or written.
        canceled.store(true, Ordering::Release);
        assert_eq!(all.read_at(0, &mut buf), None);
        assert_eq!(all.write_at(0, b"x"), None);
        assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
    }
}
