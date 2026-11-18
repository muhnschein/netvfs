// SPDX-License-Identifier: LGPL-2.1-or-later
//! FTPS server text: control replies through the reply reader, listing lines through the MLSD parser. No
//! panic; caps hold; entry names are one component.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_ftps::mlsx::{self, Line};
use netvfs_ftps::reply::{self, MAX_LINE, MAX_REPLY};

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let mut input = data;
        while let Ok(r) = reply::read(&mut input).await {
            assert!((100..600).contains(&r.code));
            assert!(r.lines.iter().all(|l| l.len() <= MAX_LINE));
            assert!(r.lines.iter().map(Vec::len).sum::<usize>() <= MAX_REPLY);
        }
    });
    for line in data.split(|b| *b == b'\n') {
        if let Line::Child(e) | Line::Current(e) = mlsx::parse(line) {
            assert!(!e.name.contains(&b'/'));
        }
        if let Line::Child(e) = mlsx::parse(line) {
            assert!(!e.name.is_empty() && e.name != b"." && e.name != b"..");
        }
    }
});
