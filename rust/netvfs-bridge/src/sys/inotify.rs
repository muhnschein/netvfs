// SPDX-License-Identifier: LGPL-2.1-or-later
//! inotify(7): a non-blocking instance, watches, and its events.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// An inotify instance (`IN_NONBLOCK`, `IN_CLOEXEC`).
#[derive(Debug)]
pub struct Inotify {
    file: File,
}

/// One event: the watch, what happened, and the entry's name (empty for
/// the watched object itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The watch descriptor.
    pub wd: i32,
    /// `IN_*` bits.
    pub mask: u32,
    /// The entry in a watched folder, without the NUL padding.
    pub name: Vec<u8>,
}

/// Size of `struct inotify_event` without its name.
const HEADER: usize = 16;

impl Inotify {
    /// A new instance.
    ///
    /// # Errors
    /// When the kernel refuses one (limits, no inotify).
    pub fn new() -> io::Result<Self> {
        // SAFETY: inotify_init1 takes flags only and returns a new descriptor
        // or -1; nothing is passed by pointer.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened by this process and nothing else owns
        // it, so the OwnedFd is its only owner.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { file: File::from(owned) })
    }

    /// Watches `path` for the `IN_*` events in `mask`; returns the watch
    /// descriptor.
    ///
    /// # Errors
    /// When the path has a NUL byte or cannot be watched.
    pub fn add_watch(&self, path: &Path, mask: u32) -> io::Result<i32> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: the descriptor is open for the life of `self`, and `c_path`
        // is a NUL-terminated string that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(self.file.as_raw_fd(), c_path.as_ptr(), mask) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(wd)
    }

    /// Reads the pending events; `WouldBlock` when there are none.
    ///
    /// # Errors
    /// `WouldBlock`, or a read error.
    pub fn read_events(&self) -> io::Result<Vec<Event>> {
        // Room for many events; the kernel never splits one.
        let mut buf = vec![0u8; 16 * 1024];
        let n = (&self.file).read(&mut buf)?;
        Ok(parse_events(buf.get(..n).unwrap_or_default()))
    }
}

impl AsRawFd for Inotify {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for Inotify {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// The events of one `read()`: `struct inotify_event` records (native byte
/// order), each followed by its NUL-padded name. A truncated record ends
/// the list.
#[must_use]
pub fn parse_events(mut buf: &[u8]) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(header) = buf.get(..HEADER) {
        let field = |at: usize| {
            let bytes: [u8; 4] =
                header.get(at..at.saturating_add(4)).and_then(|b| b.try_into().ok()).unwrap_or_default();
            u32::from_ne_bytes(bytes)
        };
        let len = usize::try_from(field(12)).unwrap_or(usize::MAX);
        let Some(name) = buf.get(HEADER..HEADER.saturating_add(len)) else { break };
        let name = name.iter().take_while(|b| **b != 0).copied().collect();
        events.push(Event { wd: i32::from_ne_bytes(field(0).to_ne_bytes()), mask: field(4), name });
        buf = buf.get(HEADER.saturating_add(len)..).unwrap_or_default();
    }
    events
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn record(wd: i32, mask: u32, name: &[u8], len: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&wd.to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(name);
        out.resize(out.len() + len as usize - name.len(), 0);
        out
    }

    #[test]
    fn parses_records() {
        let mut buf = record(1, libc::IN_CLOSE_WRITE, b"bridge.conf", 16);
        buf.extend(record(-1, libc::IN_Q_OVERFLOW, b"", 0));
        buf.extend(record(2, libc::IN_IGNORED, b"x", 4));
        assert_eq!(
            parse_events(&buf),
            [
                Event { wd: 1, mask: libc::IN_CLOSE_WRITE, name: b"bridge.conf".to_vec() },
                Event { wd: -1, mask: libc::IN_Q_OVERFLOW, name: Vec::new() },
                Event { wd: 2, mask: libc::IN_IGNORED, name: b"x".to_vec() },
            ]
        );
        // A record cut short ends the list.
        let mut cut = record(1, 2, b"abc", 8);
        cut.truncate(20);
        assert!(parse_events(&cut).is_empty());
        assert!(parse_events(&cut[..10]).is_empty());
    }

    #[test]
    fn watches_a_folder() {
        let dir = std::env::temp_dir().join(format!("nvb-inotify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let inotify = Inotify::new().unwrap();
        assert!(inotify.as_raw_fd() >= 0);
        assert_eq!(inotify.as_fd().as_raw_fd(), inotify.as_raw_fd());
        let wd = inotify.add_watch(&dir, libc::IN_CLOSE_WRITE).unwrap();
        assert_eq!(inotify.read_events().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        std::fs::write(dir.join("f"), b"x").unwrap();
        assert_eq!(
            inotify.read_events().unwrap(),
            [Event { wd, mask: libc::IN_CLOSE_WRITE, name: b"f".to_vec() }]
        );
        assert_eq!(
            inotify.add_watch(&dir.join("missing"), libc::IN_CLOSE_WRITE).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(inotify.add_watch(Path::new("a\0b"), 1).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
