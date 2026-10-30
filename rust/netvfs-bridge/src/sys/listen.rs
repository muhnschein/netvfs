// SPDX-License-Identifier: LGPL-2.1-or-later
//! The listening socket systemd passes as fd 3 (`sd_listen_fds`: `LISTEN_PID`, `LISTEN_FDS`, read by `crate::server::listener`), checked to be a listening unix stream socket.

use super::{check, socket_option_int};
use std::io;
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

/// `SD_LISTEN_FDS_START`.
pub const LISTEN_FDS_START: RawFd = 3;

static TAKEN: AtomicBool = AtomicBool::new(false);

/// Takes ownership of the first socket systemd passed. Once per process: a second call fails, so fd 3 never has two owners.
pub fn take_systemd_socket() -> io::Result<OwnedFd> {
    if TAKEN.swap(true, Ordering::SeqCst) {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "the systemd socket was already taken"));
    }
    take_fd(LISTEN_FDS_START)
}

/// Takes ownership of `fd` if open; sets close-on-exec (as libdbus did).
fn take_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl on an integer descriptor; F_GETFD reads flags, EBADF if closed.
    let flags = check(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    // SAFETY: as above; F_SETFD only sets close-on-exec.
    check(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) })?;
    // SAFETY: `fd` is open (checked) and passed by the parent; `take_systemd_socket` gives it one owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Listener on `fd`, a listening unix stream socket; set non-blocking.
pub fn adopt_listener(fd: OwnedFd) -> io::Result<UnixListener> {
    let wrong =
        |what: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("the passed socket is {what}"));
    let domain = socket_option_int(fd.as_fd(), libc::SOL_SOCKET, libc::SO_DOMAIN)
        .map_err(|e| io::Error::new(e.kind(), format!("the passed descriptor is not a socket: {e}")))?;
    if domain != libc::AF_UNIX {
        return Err(wrong("not a unix socket"));
    }
    if socket_option_int(fd.as_fd(), libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_STREAM {
        return Err(wrong("not a stream socket"));
    }
    if socket_option_int(fd.as_fd(), libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? == 0 {
        return Err(wrong("not listening"));
    }
    let listener = UnixListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd as _, IntoRawFd as _};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn adopts_only_listening_unix_stream_sockets() {
        let dir = std::env::temp_dir().join(format!("nvb-listen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        drop(std::fs::remove_file(&path));
        let listener = UnixListener::bind(&path).unwrap();
        let adopted = adopt_listener(OwnedFd::from(listener)).unwrap();
        assert_eq!(adopted.local_addr().unwrap().as_pathname(), Some(path.as_path()));
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(adopt_listener(OwnedFd::from(file)).unwrap_err().to_string().contains("not a socket"));
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(adopt_listener(OwnedFd::from(a)).unwrap_err().to_string().contains("not listening"));
        let (d, _e) = UnixDatagram::pair().unwrap();
        assert!(adopt_listener(OwnedFd::from(d)).unwrap_err().to_string().contains("not a stream"));
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(adopt_listener(OwnedFd::from(tcp)).unwrap_err().to_string().contains("not a unix"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn takes_an_open_descriptor_and_marks_it_cloexec() {
        let (a, _b) = UnixStream::pair().unwrap();
        let raw = a.into_raw_fd();
        // SAFETY: test only; descriptor owned by the test.
        unsafe { libc::fcntl(raw, libc::F_SETFD, 0) };
        let owned = take_fd(raw).unwrap();
        // SAFETY: test only; descriptor owned by the test.
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        drop(owned);
        assert!(take_fd(raw).is_err());
        let raw = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        let owned = take_fd(raw).unwrap();
        // SAFETY: test only; descriptor owned by the test.
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    #[test]
    fn the_systemd_socket_is_taken_once() {
        let first = take_systemd_socket();
        let second = take_systemd_socket();
        assert_eq!(second.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        if let Ok(fd) = first {
            let _given_back = fd.into_raw_fd();
        }
    }
}
