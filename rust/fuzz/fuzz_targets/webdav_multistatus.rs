// SPDX-License-Identifier: LGPL-2.1-or-later
//! WebDAV multistatus body through the PROPFIND parser. No panic; caps hold; every path is absolute, decoded,
//! without NUL.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_webdav::paths::MAX_HREF;
use netvfs_webdav::xml::{MAX_RESPONSES, MAX_TEXT, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(all) = parse(data) else { return };
    assert!(all.len() <= MAX_RESPONSES);
    for r in all {
        assert!(r.path.len() <= MAX_HREF && r.path.first() == Some(&b'/') && !r.path.contains(&0));
        assert!(r.props.etag.len() <= MAX_TEXT && r.props.content_type.len() <= MAX_TEXT);
    }
});
