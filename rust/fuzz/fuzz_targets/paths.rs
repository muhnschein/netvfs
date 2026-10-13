// SPDX-License-Identifier: LGPL-2.1-or-later
//! Byte paths from a consumer (XSEC-7): normalisation either fails or gives
//! a path that is normalised already.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_bridge::server::paths::normalize;

fuzz_target!(|data: &[u8]| {
    if let Ok(path) = normalize(data) {
        let again = normalize(path.as_bytes()).expect("a normalised path stays valid");
        assert_eq!(again.as_bytes(), path.as_bytes());
    }
});
