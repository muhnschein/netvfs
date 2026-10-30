// SPDX-License-Identifier: LGPL-2.1-or-later
//! `libnetvfs-rs.so`: the Rust backends behind the C++ backend plugins.
//!
//! - [`ffi`]: C ABI table handed out by `nvr_get`, the one export.
//! - `runtime`: one tokio runtime per process; calls `block_on` on the caller's thread, cut 1 s after a cancel.
//! - `erased`: netvfs-vfs traits behind `dyn`, backends picked by provider name.
//! - `mem` (feature `testing`): in-memory backend, provider `mem`.
//!
//! Built with the `rs-release` profile (`panic = "unwind"`: a panic must reach the table function that reports it).

mod erased;
pub mod ffi;
#[cfg(feature = "testing")]
mod mem;
mod providers;
mod runtime;

pub use ffi::nvr_get;
pub use runtime::{GRACE, THREAD_PREFIX, WORKERS};
