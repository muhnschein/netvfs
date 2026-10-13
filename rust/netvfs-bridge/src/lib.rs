// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge (SPEC-v2 §8a) in Rust: everything a sandboxed consumer
//! sends is decoded and checked here; the C++ backends are reached through
//! the C ABI of `libnetvfs-bridge-ffi.so`.
//!
//! The platform part: consumer registration and paths (`config`), logging
//! (`log`), consent and its notification (`consent`, `prompt`), the
//! settings handoff (`handoff`), the accounts helper (`accounts`) and known
//! hosts (`locations::knownhosts`). `unsafe` is confined to `sys`.

pub mod accounts;
pub mod config;
pub mod consent;
pub mod handoff;
pub mod ini;
pub mod locations;
pub mod lockfile;
pub mod log;
pub mod prompt;
pub mod savefile;
pub mod status;
pub mod sys;

#[cfg(any(test, feature = "testing"))]
pub mod testutil;
