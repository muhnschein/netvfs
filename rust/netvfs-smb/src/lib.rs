// SPDX-License-Identifier: LGPL-2.1-or-later
//! An SMB 3.1.1-only client, the `smb` provider of libnetvfs-rs.so (phase 3
//! design §5, doc/RUST.md "netvfs-smb").
#![forbid(unsafe_code)]

pub mod crypto;
