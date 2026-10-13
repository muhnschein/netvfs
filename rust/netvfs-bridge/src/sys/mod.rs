// SPDX-License-Identifier: LGPL-2.1-or-later
//! The calls into libc (and the one `unsafe` constructor of zbus) that the
//! socket front needs. The only module of the crate with `unsafe` code
//! besides `ffi` (design §6.12); every block has its SAFETY comment and
//! every function a safe signature.
#![allow(unsafe_code)]

pub mod frame;
pub mod listen;
pub mod peer;

use std::io;

/// `Ok(value)` for a libc return value that is not -1, the OS error otherwise.
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
    // SAFETY: `fd` is a valid descriptor for the call (borrowed), `value` and
    // `length` are live locals of the size `length` announces.
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
        // An option that does not exist: the OS error comes back.
        assert!(socket_option_int(a.as_fd(), libc::SOL_SOCKET, 99_999).is_err());
        assert_eq!(check(0).unwrap(), 0);
        assert_eq!(check(7).unwrap(), 7);
        assert!(check(-1).is_err());
    }
}
