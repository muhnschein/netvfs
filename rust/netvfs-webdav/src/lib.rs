// SPDX-License-Identifier: LGPL-2.1-or-later
//! A WebDAV client over HTTPS (TLS 1.3, HTTP/1.1, Basic auth), the `webdav` provider of libnetvfs-rs.so.
#![forbid(unsafe_code)]

pub mod backend;
#[cfg(test)]
mod fake;
pub mod http;
pub mod io;
pub mod paths;
pub mod status;
pub mod xml;
