// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge (SPEC-v2 §8a) in Rust: everything a sandboxed consumer
//! sends is decoded and checked here; the C++ backends are reached through
//! the C ABI of `libnetvfs-bridge-ffi.so` (module `ffi`, doc/RUST.md).

pub mod ffi;
pub mod status;

pub use status::Status;
