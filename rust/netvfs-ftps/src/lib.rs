// SPDX-License-Identifier: LGPL-2.1-or-later
//! An FTPS client (explicit `AUTH TLS`, TLS 1.3 only, protected data, `MLSD`/`MLST`, `EPSV`), the `ftps`
//! provider of libnetvfs-rs.so.
#![forbid(unsafe_code)]

pub mod backend;
pub mod ctrl;
#[cfg(test)]
mod fake;
pub mod mlsx;
pub mod reply;
