// SPDX-License-Identifier: LGPL-2.1-or-later
//! `libnetvfs-rs.so`: the Rust backends behind the C++ backend plugins
//! (phase 3 design §1, doc/RUST.md "netvfs-backend").
//!
//! - [`ffi`]: the C ABI of `src/backends/rs/netvfs_rs.h`, the table that
//!   `nvr_get`, the library's one export, hands out.
//! - `runtime`: one tokio runtime per process (two `nvr-io-*` workers);
//!   every call runs with `block_on` on the caller's thread, and is cut
//!   1 s after a cancel that it does not end itself (C-9).
//! - `erased`: the netvfs-vfs traits behind `dyn`, for backends picked by
//!   provider name.
//! - `mem` (feature `testing`): an in-memory backend, provider `mem`, for
//!   the shim's tests and the conformance suite.
//!
//! The library is built with the `rs-release` profile (`panic = "unwind"`,
//! so that a panic reaches the table function that reports it); see
//! rust/Cargo.toml.

mod erased;
pub mod ffi;
#[cfg(feature = "testing")]
mod mem;
mod providers;
mod runtime;

pub use ffi::nvr_get;
pub use runtime::{GRACE, THREAD_PREFIX, WORKERS};
