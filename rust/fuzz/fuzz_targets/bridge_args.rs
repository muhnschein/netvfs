// SPDX-License-Identifier: LGPL-2.1-or-later
//! Consumer call body bytes, any signature, through the argument decoder.
//! Byte 0 picks the method; bit 0 of byte 1 set: signature read up to a NUL; rest is body.
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
        // Wire signature max 255 bytes; zbus builder panics on more.
        let Ok(signature) = std::str::from_utf8(&rest[..end.min(255)]) else { return };
        (signature, rest.get(end + 1..).unwrap_or_default())
    } else {
        (method.input, rest)
    };
    let Ok(builder) = Message::method_call(OBJECT_PATH, method.name).and_then(|b| b.interface(INTERFACE)) else {
        return;
    };
    // SAFETY: body may not match the signature; the decoder must cope. No descriptors attached.
    let Ok(message) = (unsafe { builder.build_raw_body(body, signature, Vec::new()) }) else { return };
    let _ = decode(&message);
});
