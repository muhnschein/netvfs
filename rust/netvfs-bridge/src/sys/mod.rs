// SPDX-License-Identifier: LGPL-2.1-or-later
//! libc calls (and `unsafe` zbus/tokio constructors), each in a safe wrapper. Only `unsafe` module besides `ffi`.
#![allow(unsafe_code)]

#[cfg(any(test, feature = "testing"))]
pub mod child;
pub mod fd;
pub mod frame;
pub mod inotify;
pub mod listen;
pub mod lock;
pub mod peer;

use std::io;

/// `Ok(value)` unless -1, else the OS error.
fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result == -1 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

/// Reads an `int` socket option.
fn socket_option_int(
    fd: std::os::fd::BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    use std::os::fd::AsRawFd as _;
    let mut value: libc::c_int = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(0);
    // SAFETY: `fd` valid and borrowed; `value` and `length` are live locals of the announced size.
    let result =
        unsafe { libc::getsockopt(fd.as_raw_fd(), level, name, (&raw mut value).cast(), &raw mut length) };
    check(result)?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::net::UnixStream;

    #[test]
    fn socket_options_and_errors() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(socket_option_int(a.as_fd(), libc::SOL_SOCKET, libc::SO_TYPE).unwrap(), libc::SOCK_STREAM);
        assert!(socket_option_int(a.as_fd(), libc::SOL_SOCKET, 99_999).is_err());
        assert_eq!(check(0).unwrap(), 0);
        assert_eq!(check(7).unwrap(), 7);
        assert!(check(-1).is_err());
    }
}
