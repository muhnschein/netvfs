// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-accounts: see the library.

/// The weekly ASan run only (`--cfg netvfs_asan`, tools/ci/rust-sanitize.sh):
/// a set-id start cannot read `ASAN_OPTIONS` (its /proc/self/environ is not
/// readable), and LeakSanitizer cannot stop the confined helper (no ptrace),
/// so leak checking is off from the start.
#[cfg(netvfs_asan)]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(netvfs_accounts::run())
}
