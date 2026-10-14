// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SFTP backend (phase 3 design §4).
#![forbid(unsafe_code)]

pub mod client;
pub mod errors;
pub mod paths;
pub mod proto;
pub mod wire;

#[cfg(test)]
mod fake;
