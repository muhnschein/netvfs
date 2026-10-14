// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SFTP backend (phase 3 design §4).
#![forbid(unsafe_code)]

pub mod auth;
pub mod backend;
pub mod client;
pub mod errors;
pub mod io;
pub mod keys;
pub mod paths;
pub mod policy;
pub mod proto;
pub mod remote;
pub mod session;
pub mod wire;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod testserver;
