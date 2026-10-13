// SPDX-License-Identifier: LGPL-2.1-or-later
//! Who is on the other end of a unix socket: `SO_PEERCRED`, `SO_PEERPIDFD`
//! (Linux 6.5), `pidfd_open` (Linux 5.3), and the clock of `/proc/<pid>/stat`
//! (XB-5; the policy is in `crate::peer`).

use super::{check, socket_option_int};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// `SO_PEERPIDFD` (Linux 6.5), which the libc crate does not name yet; the
/// value of the generic socket option table (x86, arm, aarch64).
const SO_PEERPIDFD: libc::c_int = 77;

/// The credentials of a connected unix socket's peer.
#[derive(Debug)]
pub struct PeerCredentials {
    /// The process that connected (at connect time).
    pub pid: i32,
    /// Its effective uid.
    pub uid: u32,
    /// A pidfd of exactly that process, where the kernel has `SO_PEERPIDFD`.
    pub pidfd: Option<OwnedFd>,
}

/// `SO_PEERCRED` of `socket`, plus `SO_PEERPIDFD` where available.
pub fn credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let expected = libc::socklen_t::try_from(size_of::<libc::ucred>()).unwrap_or(0);
    let mut length = expected;
    // SAFETY: `socket` is a valid descriptor (borrowed for the call); `cred`
    // and `length` are live locals and `length` is the size of `cred`.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut length,
        )
    };
    check(result)?;
    if length != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short SO_PEERCRED"));
    }
    let pidfd = socket_option_int(socket, libc::SOL_SOCKET, SO_PEERPIDFD).ok().and_then(owned_fd);
    Ok(PeerCredentials { pid: cred.pid, uid: cred.uid, pidfd })
}

/// `pidfd_open(pid, 0)`; `None` where the kernel has no pidfds or the
/// process is gone.
pub fn pidfd_open(pid: i32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open takes two integers and returns a new descriptor
    // or -1; no memory is passed.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::c_long::from(pid), 0_u32) };
    libc::c_int::try_from(result).ok().and_then(owned_fd)
}

/// Takes ownership of a descriptor a syscall just returned to us.
fn owned_fd(fd: libc::c_int) -> Option<OwnedFd> {
    // SAFETY: only called with descriptors the kernel has just created for
    // this process (SO_PEERPIDFD, pidfd_open), which nothing else owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The effective uid of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Clock ticks per second (`sysconf(_SC_CLK_TCK)`), the unit of
/// `/proc/<pid>/stat` start times; `None` if unknown.
pub fn clock_ticks_per_second() -> Option<i64> {
    // SAFETY: sysconf takes an integer and returns an integer.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    #[allow(clippy::useless_conversion, reason = "c_long is i32 on 32-bit targets")]
    (hz > 0).then(|| i64::from(hz))
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn credentials_of_a_socketpair_are_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = credentials(a.as_fd()).unwrap();
        assert_eq!(cred.pid, i32::try_from(std::process::id()).unwrap());
        assert_eq!(cred.uid, effective_uid());
    }

    #[test]
    fn credentials_of_a_non_socket_fail() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(credentials(file.as_fd()).is_err());
    }

    #[test]
    fn pidfd_of_ourselves_and_of_nobody() {
        let own = i32::try_from(std::process::id()).unwrap();
        // Kernels before 5.3 have no pidfd_open: then nothing to check.
        if let Some(fd) = pidfd_open(own) {
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
            assert!(info.lines().any(|l| l.split_whitespace().eq(["Pid:".to_owned(), own.to_string()])));
        }
        assert!(pidfd_open(-1).is_none());
        assert!(owned_fd(-1).is_none());
    }

    #[test]
    fn clock_and_uid() {
        assert!(clock_ticks_per_second().unwrap() >= 1);
        assert_eq!(
            effective_uid(),
            std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap()
        );
    }
}
