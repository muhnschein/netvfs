// SPDX-License-Identifier: LGPL-2.1-or-later
//! `flock()` and `kill(pid, 0)` for the `QLockFile`-compatible lock.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// `flock(fd, LOCK_EX | LOCK_NB)` as `QLockFile`.
///
/// # Errors
/// `WouldBlock` when another descriptor holds it.
pub fn lock_exclusive_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: flock takes a live descriptor and flags; no pointers.
    let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Whether `pid` exists: `kill(pid, 0)` fails with `ESRCH` only when not (`EPERM`: exists).
#[must_use]
pub fn process_exists(pid: i32) -> bool {
    if pid <= 0 {
        // 0 and negative pids name process groups.
        return false;
    }
    // SAFETY: signal 0 sends nothing.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn flock_is_exclusive() {
        let path = std::env::temp_dir().join(format!("nvb-flock-{}", std::process::id()));
        let first = std::fs::File::create(&path).unwrap();
        let second = std::fs::File::open(&path).unwrap();
        lock_exclusive_nonblocking(first.as_fd()).unwrap();
        assert_eq!(lock_exclusive_nonblocking(second.as_fd()).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        drop(first);
        lock_exclusive_nonblocking(second.as_fd()).unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn processes() {
        assert!(process_exists(i32::try_from(std::process::id()).unwrap()));
        assert!(process_exists(1));
        assert!(!process_exists(0));
        assert!(!process_exists(-1));
        assert!(!process_exists(i32::MAX));
    }
}
