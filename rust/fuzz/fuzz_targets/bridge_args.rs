// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a consumer sends to netvfs-bridge (XSEC-7): any body bytes, under
//! the method's own signature or any other, through the argument decoder.
//!
//! Input: byte 0 picks the method of the table; when bit 0 of byte 1 is
//! set, the signature is read from the following bytes up to a NUL;
//! the rest is the body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_bridge::server::args::decode;
use netvfs_bridge_proto::{INTERFACE, METHODS, OBJECT_PATH};
use zbus::Message;

fuzz_target!(|data: &[u8]| {
    let [pick, flags, rest @ ..] = data else { return };
    let method = &METHODS[usize::from(*pick) % METHODS.len()];
    let (signature, body) = if flags & 1 == 1 {
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        // The wire holds at most 255 signature bytes; zbus's builder panics
        // on more instead of failing.
        let Ok(signature) = std::str::from_utf8(&rest[..end.min(255)]) else { return };
        (signature, rest.get(end + 1..).unwrap_or_default())
    } else {
        (method.input, rest)
    };
    let Ok(builder) = Message::method_call(OBJECT_PATH, method.name).and_then(|b| b.interface(INTERFACE)) else {
        return;
    };
    // SAFETY: `build_raw_body` is unsafe only because the body may not match
    // the signature; the decoder must cope with exactly that. No descriptors
    // are attached.
    let Ok(message) = (unsafe { builder.build_raw_body(body, signature, Vec::new()) }) else { return };
    let _ = decode(&message);
});
