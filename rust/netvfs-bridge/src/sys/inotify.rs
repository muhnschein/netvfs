// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use tokio::io::unix::AsyncFd;

#[derive(Debug)]
pub struct Inotify {
    file: File,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub wd: i32,
    pub mask: u32,
    pub name: Vec<u8>,
}

const HEADER: usize = 16;

impl Inotify {
    pub fn new() -> io::Result<Self> {
        // SAFETY: inotify_init1 takes flags, returns a descriptor or -1; no pointers.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` just opened by this process, nothing else owns it.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { file: File::from(owned) })
    }

    pub fn add_watch(&self, path: &Path, mask: u32) -> io::Result<i32> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: descriptor open for the life of `self`; `c_path` is NUL-terminated and outlives the call.
        let wd = unsafe { libc::inotify_add_watch(self.file.as_raw_fd(), c_path.as_ptr(), mask) };
        if wd == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(wd)
    }

    pub fn read_events(&self) -> io::Result<Vec<Event>> {
        let mut buf = vec![0u8; 16 * 1024];
        let n = (&self.file).read(&mut buf)?;
        Ok(parse_events(buf.get(..n).unwrap_or_default()))
    }

    pub fn register(self) -> io::Result<AsyncFd<Self>> {
        // SAFETY: instance owns its descriptor (private `file`, never replaced); it stays open and the same until the AsyncFd drops.
        unsafe { AsyncFd::register(self) }.map_err(io::Error::from)
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
        let mut cut = record(1, 2, b"abc", 8);
        cut.truncate(20);
        assert_eq!(parse_events(&cut).len(), 0);
        assert_eq!(parse_events(&cut[..10]).len(), 0);
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
