// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge (SPEC-v2 §8a) in Rust: everything a sandboxed consumer
//! sends is decoded and checked here; the C++ backends are reached through
//! the C ABI of `libnetvfs-bridge-ffi.so` ([`ffi`], doc/RUST.md).
//!
//! The socket front (design §3.2): the peer check ([`peer`], XB-5), the
//! listener and the per-connection sessions over a zbus peer-to-peer server,
//! the dispatch of raw D-Bus messages, the argument validation into typed
//! calls ([`server::args`], XSEC-7), the encoding of replies and signals, and
//! flow control (C-10). The core (consent, locations, jobs) receives
//! [`server::Event`]s and answers through [`server::ReplyTo`] and
//! [`server::Outbox`]; see [`server`] for that contract.
//!
//! The backend side (design §3.3): [`locations`] holds the locations, their
//! connection pools and the worker threads that own the backend
//! connections; [`jobs`] has the bodies those workers run for listings,
//! walks, removals and transfers.
//!
//! The platform part: consumer registration and paths ([`config`]),
//! logging ([`log`]), consent and its notification ([`consent`],
//! [`prompt`]), the settings handoff ([`handoff`]), the accounts helper
//! ([`accounts`]) and known hosts ([`locations::knownhosts`]). `unsafe` is
//! confined to `ffi` and `sys`.

pub mod accounts;
pub mod config;
pub mod consent;
pub mod core;
pub mod ffi;
pub mod handoff;
pub mod ini;
pub mod jobs;
pub mod locations;
pub mod lockfile;
pub mod log;
pub mod peer;
pub mod prompt;
pub mod savefile;
pub mod server;
/// [`Status`], shared with the backends ([`netvfs_vfs::status`]).
pub use netvfs_vfs::status;
mod sys;
#[cfg(test)]
mod test_support;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(any(test, feature = "testing"))]
pub mod testutil;

pub use crate::core::{Config, CoreLink, Counters, Deps, Services};
pub use status::Status;

use std::process::ExitCode;

/// Serves one consumer (XB-3) until the idle exit (XB-2): binds the
/// listening socket of `deps`, then runs the [`core`](crate::core) on a
/// current-thread runtime of the calling thread (the runtime thread, T1).
/// The C ABI must be loaded and `init`ed, its Qt loop running on the main
/// thread. Success after the idle exit or [`CoreLink::shutdown`]; failure
/// when the socket cannot be bound or the runtime cannot start.
#[must_use]
pub fn serve(config: Config, deps: Deps) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            log::critical(format_args!("Cannot start the runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Inside the runtime's context until the end: tasks the core leaves
    // behind (a session-bus connection among them) are dropped with the
    // LocalSet, and zbus spawns its cleanup onto the runtime as they go.
    let _context = runtime.enter();
    let local = tokio::task::LocalSet::new();
    let code = local.block_on(&runtime, core::run(config, deps));
    drop(local);
    code
}
