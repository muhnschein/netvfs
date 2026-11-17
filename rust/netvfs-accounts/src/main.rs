// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-accounts: see the library.

// ASan runs only (`--cfg netvfs_asan`): set-id start cannot read `ASAN_OPTIONS`, and
// LeakSanitizer cannot stop the confined helper (no ptrace).
#[cfg(netvfs_asan)]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
extern "C" fn __asan_default_options() -> *const std::ffi::c_char {
    c"detect_leaks=0".as_ptr()
}

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(netvfs_accounts::run())
}
