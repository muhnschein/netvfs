// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-bridge (SPEC-v2 §8a) in Rust: everything a sandboxed consumer
//! sends is decoded and checked here.
//!
//! This part is the socket front (design §3.2, chunk D): the peer check
//! ([`peer`], XB-5), the listener and the per-connection sessions over a zbus
//! peer-to-peer server, the dispatch of raw D-Bus messages, the argument
//! validation into typed calls ([`server::args`], XSEC-7), the encoding of
//! replies and signals, and flow control (C-10). The core (consent, locations,
//! jobs) receives [`server::Event`]s and answers through [`server::ReplyTo`]
//! and [`server::Outbox`]; see [`server`] for that contract.

pub mod peer;
pub mod server;
pub mod status;
mod sys;
#[cfg(test)]
mod test_support;

pub use status::Status;
