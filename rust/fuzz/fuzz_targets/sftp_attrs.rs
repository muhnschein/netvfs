// SPDX-License-Identifier: LGPL-2.1-or-later
//! SFTP v3 attribute blocks: decode never panics; decoded attrs re-encode to the same attrs; entry keeps permission bits within 0o7777.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_sftp::proto::Attrs;
use netvfs_sftp::remote::entry_from;
use netvfs_sftp::wire::{Packet, Reader};
use netvfs_vfs::EntryType;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::new(data);
    let Ok(attrs) = Attrs::decode(&mut reader) else {
        return;
    };
    let packet = attrs.encode(Packet::request(0)).finish(7).expect("an attribute block fits a packet");
    let mut again = Reader::new(&packet[9..]);
    assert_eq!(Attrs::decode(&mut again), Ok(attrs));
    assert!(again.is_empty(), "the block is all that was written");

    let entry = entry_from(&attrs, b"name");
    assert_eq!(entry.name, b"name");
    assert_eq!(entry.size, attrs.size);
    if let Some(mode) = entry.mode {
        assert!(mode <= 0o7777);
    }
    let kind = attrs.permissions.map(|p| p & 0o170_000);
    match kind {
        Some(0o040_000) => assert_eq!(entry.kind, EntryType::Directory),
        Some(0o100_000) => assert_eq!(entry.kind, EntryType::File),
        Some(0o120_000) => assert_eq!(entry.kind, EntryType::Symlink),
        _ => {}
    }
});
