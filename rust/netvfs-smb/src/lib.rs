// SPDX-License-Identifier: LGPL-2.1-or-later
//! An SMB 3.1.1-only client, the `smb` provider of libnetvfs-rs.so (phase 3
//! design §5, doc/RUST.md "netvfs-smb").
#![forbid(unsafe_code)]

pub mod auth;
pub mod backend;
pub mod conn;
pub mod crypto;
pub mod error;
#[cfg(test)]
mod fake;
pub mod files;
pub mod fs;
pub mod msg;
pub mod names;
pub mod negotiate;
pub mod profile;
pub mod rpc;
pub mod session;
pub mod status;
pub mod transport;
pub mod wire;
