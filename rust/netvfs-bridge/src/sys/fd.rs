// SPDX-License-Identifier: LGPL-2.1-or-later
//! The descriptor calls of transfers (XB-11): what a descriptor is
//! (`fstat`, `F_GETFL`), positioned reads and writes of regular files
//! (`pread`, `pwrite`), sequential ones of FIFOs (`read`, `write`) and
//! waiting for a FIFO (`poll`). The checks themselves and the device over a
//! checked descriptor are in `crate::jobs::fd` and `crate::jobs::fdio`.
//!
//! An interrupted call (`EINTR`) is repeated; `poll` reports it as "not
//! ready yet", so that its caller looks at its cancel flag again.

use super::check;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, RawFd};

/// The type of a file, from `st_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// `S_IFREG`.
    Regular,
    /// `S_IFIFO`.
    Fifo,
    /// Anything else (folder, socket, device, link).
    Other,
}

/// What `fstat` says about a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// The file's type.
    pub kind: FileKind,
    /// `st_size`.
    pub size: i64,
}

/// `fstat(fd)`. Any number may be asked about: `fstat` only reads the
/// descriptor table (`EBADF` for one that is not open).
///
/// # Errors
/// The OS error (`EBADF`, …).
pub fn stat(fd: RawFd) -> io::Result<FileStat> {
    // SAFETY: an all-zero `stat` is a valid value of the plain C struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a live local of the right type; `fd` is only looked up.
    check(unsafe { libc::fstat(fd, &raw mut st) })?;
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => FileKind::Regular,
        libc::S_IFIFO => FileKind::Fifo,
        _ => FileKind::Other,
    };
    Ok(FileStat { kind, size: st.st_size })
}

/// `fcntl(fd, F_GETFL)`: the descriptor's status flags (`O_ACCMODE`,
/// `O_APPEND`, `O_PATH`, …). Any number may be asked about.
///
/// # Errors
/// The OS error (`EBADF`, …).
pub fn status_flags(fd: RawFd) -> io::Result<libc::c_int> {
    // SAFETY: F_GETFL takes no argument and only reads the descriptor table.
    check(unsafe { libc::fcntl(fd, libc::F_GETFL) })
}

/// The count of a `read`-like call, or its OS error.
fn count(n: libc::ssize_t) -> io::Result<usize> {
    usize::try_from(n).map_err(|_negative| io::Error::last_os_error())
}

/// Repeats `call` while it fails with `EINTR`.
fn retry(mut call: impl FnMut() -> libc::ssize_t) -> io::Result<usize> {
    loop {
        match count(call()) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `pread`: reads into `buf` at `offset` of the file; the descriptor's own
/// offset is neither used nor moved.
///
/// # Errors
/// The OS error; `InvalidInput` for an offset `off_t` cannot hold.
pub fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], offset: i64) -> io::Result<usize> {
    let offset =
        libc::off_t::try_from(offset).map_err(|_too_big| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `buf` is writable for `buf.len()` bytes during the call; `fd`
    // is a live descriptor (borrowed).
    retry(|| unsafe { libc::pread(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), offset) })
}

/// `pwrite`: writes `data` at `offset` of the file; the descriptor's own
/// offset is neither used nor moved. May write fewer bytes.
///
/// # Errors
/// The OS error; `InvalidInput` for an offset `off_t` cannot hold.
pub fn pwrite(fd: BorrowedFd<'_>, data: &[u8], offset: i64) -> io::Result<usize> {
    let offset =
        libc::off_t::try_from(offset).map_err(|_too_big| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `data` is readable for `data.len()` bytes during the call;
    // `fd` is a live descriptor (borrowed).
    retry(|| unsafe { libc::pwrite(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), offset) })
}

/// `read` (a FIFO): 0 at the end.
///
/// # Errors
/// The OS error.
pub fn read(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for `buf.len()` bytes during the call; `fd`
    // is a live descriptor (borrowed).
    retry(|| unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) })
}

/// `write` (a FIFO): may write fewer bytes.
///
/// # Errors
/// The OS error (`EPIPE` once the reader is gone).
pub fn write(fd: BorrowedFd<'_>, data: &[u8]) -> io::Result<usize> {
    // SAFETY: `data` is readable for `data.len()` bytes during the call;
    // `fd` is a live descriptor (borrowed).
    retry(|| unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) })
}

/// What a descriptor is waited for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
    /// Data to read (or the end).
    Read,
    /// Room to write (or the reader is gone).
    Write,
}

/// `poll` on one descriptor for at most `timeout_ms`: true when it is ready
/// (also for an error or hang-up, which the next read or write reports),
/// false when the time passed or the call was interrupted.
///
/// # Errors
/// The OS error other than `EINTR`.
pub fn poll(fd: BorrowedFd<'_>, ready: Ready, timeout_ms: i32) -> io::Result<bool> {
    let events = match ready {
        Ready::Read => libc::POLLIN,
        Ready::Write => libc::POLLOUT,
    };
    let mut p = libc::pollfd { fd: fd.as_raw_fd(), events, revents: 0 };
    // SAFETY: one live `pollfd` for the call; `fd` is a live descriptor.
    match check(unsafe { libc::poll(&raw mut p, 1, timeout_ms) }) {
        Ok(n) => Ok(n > 0),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, write_file};
    use std::fs::{File, OpenOptions};
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn pipe() -> (File, File) {
        let (r, w) = io::pipe().unwrap();
        (File::from(std::os::fd::OwnedFd::from(r)), File::from(std::os::fd::OwnedFd::from(w)))
    }

    #[test]
    fn stat_and_flags() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_file(&path, b"0123456789");
        let file = File::open(&path).unwrap();
        assert_eq!(stat(file.as_raw_fd()).unwrap(), FileStat { kind: FileKind::Regular, size: 10 });
        assert_eq!(status_flags(file.as_raw_fd()).unwrap() & libc::O_ACCMODE, libc::O_RDONLY);
        let append = OpenOptions::new().append(true).open(&path).unwrap();
        let flags = status_flags(append.as_raw_fd()).unwrap();
        assert_eq!((flags & libc::O_ACCMODE, flags & libc::O_APPEND), (libc::O_WRONLY, libc::O_APPEND));
        let (r, _w) = pipe();
        assert_eq!(stat(r.as_raw_fd()).unwrap().kind, FileKind::Fifo);
        let folder = File::open(dir.path()).unwrap();
        assert_eq!(stat(folder.as_raw_fd()).unwrap().kind, FileKind::Other);
        let (sock, _peer) = UnixStream::pair().unwrap();
        assert_eq!(stat(sock.as_raw_fd()).unwrap().kind, FileKind::Other);
        assert_eq!(stat(-1).unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(status_flags(-1).unwrap_err().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn positioned_io_leaves_the_offset() {
        let dir = TempDir::new();
        let path = dir.path().join("f");
        write_file(&path, b"0123456789");
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(pread(file.as_fd(), &mut buf, 5).unwrap(), 4);
        assert_eq!(&buf, b"5678");
        assert_eq!(pread(file.as_fd(), &mut buf, 8).unwrap(), 2);
        assert_eq!(pread(file.as_fd(), &mut buf, 10).unwrap(), 0);
        assert_eq!(pwrite(file.as_fd(), b"AB", 12).unwrap(), 2);
        assert_eq!(file.stream_position().unwrap(), 3);
        let mut all = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut all).unwrap();
        assert_eq!(all, b"0123456789\0\0AB");
        assert_eq!(pread(file.as_fd(), &mut buf, -1).unwrap_err().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(pwrite(file.as_fd(), b"x", -1).unwrap_err().raw_os_error(), Some(libc::EINVAL));
        // A read-only descriptor cannot be written, nor a write-only read.
        let ro = File::open(&path).unwrap();
        assert_eq!(pwrite(ro.as_fd(), b"x", 0).unwrap_err().raw_os_error(), Some(libc::EBADF));
        let wo = OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(pread(wo.as_fd(), &mut buf, 0).unwrap_err().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn fifo_io_and_poll() {
        let (r, w) = pipe();
        // Nothing to read: poll waits its time and says so.
        let start = Instant::now();
        assert!(!poll(r.as_fd(), Ready::Read, 50).unwrap());
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert!(poll(w.as_fd(), Ready::Write, 0).unwrap());
        assert_eq!(write(w.as_fd(), b"abc").unwrap(), 3);
        assert!(poll(r.as_fd(), Ready::Read, 1000).unwrap());
        let mut buf = [0u8; 8];
        assert_eq!(read(r.as_fd(), &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
        drop(w);
        // The writer is gone: ready, and the read says the end.
        assert!(poll(r.as_fd(), Ready::Read, 1000).unwrap());
        assert_eq!(read(r.as_fd(), &mut buf).unwrap(), 0);
        let (r2, w2) = pipe();
        drop(r2);
        assert_eq!(write(w2.as_fd(), b"x").unwrap_err().raw_os_error(), Some(libc::EPIPE));
        let (_r3, w3) = pipe();
        assert_eq!(read(w3.as_fd(), &mut buf).unwrap_err().raw_os_error(), Some(libc::EBADF));
    }
}
