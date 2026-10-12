// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the session bus sends back to the helper's announcement: any bytes,
//! as one message and through the whole exchange.
#![no_main]

use std::io::{Read, Write};

use libfuzzer_sys::fuzz_target;
use netvfs_accounts::dbus::{exchange, parse_received};

/// A bus that answers with `data` and accepts whatever is written.
struct Bus<'a>(&'a [u8]);

impl Read for Bus<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Bus<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_received(data);
    let _ = exchange(&mut Bus(data), 1000, b"payload");
});
