// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge in Rust: everything a sandboxed consumer sends is decoded and checked here; C++ backends are reached through the C ABI of `libnetvfs-bridge-ffi.so` ([`ffi`]).
//!
//! Socket front: peer check ([`peer`]), listener and per-connection sessions over a zbus p2p server, raw D-Bus dispatch, argument validation ([`server::args`]), reply and signal encoding, flow control. The core receives [`server::Event`]s and answers through [`server::ReplyTo`] and [`server::Outbox`].
//!
//! Backend side: [`locations`] holds locations, connection pools and the worker threads owning backend connections; [`jobs`] has the worker bodies.
//!
//! Platform: [`config`], [`log`], consent ([`consent`], [`prompt`]), settings handoff ([`handoff`]), accounts helper ([`accounts`]), known hosts ([`locations::knownhosts`]), UDisks2 drives ([`drives`]). `unsafe` is confined to `ffi` and `sys`.

pub mod accounts;
pub mod config;
pub mod consent;
pub mod core;
pub mod drives;
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
/// [`Status`], shared with the backends.
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

/// Serves one consumer until the idle exit: binds the listening socket of `deps`, runs the [`core`](crate::core) on a current-thread runtime of the calling thread. The C ABI must be loaded and `init`ed, its Qt loop running on the main thread. Success after idle exit or [`CoreLink::shutdown`]; failure if the socket cannot be bound or the runtime cannot start.
#[must_use]
pub fn serve(config: Config, deps: Deps) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            log::critical(format_args!("Cannot start the runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Tasks the core leaves behind (session-bus connection) drop with the LocalSet; zbus spawns its cleanup onto the runtime.
    let _context = runtime.enter();
    let local = tokio::task::LocalSet::new();
    let code = local.block_on(&runtime, core::run(config, deps));
    drop(local);
    code
}
