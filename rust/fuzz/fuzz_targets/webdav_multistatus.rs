// SPDX-License-Identifier: LGPL-2.1-or-later
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_webdav::paths::MAX_HREF;
use netvfs_webdav::xml::{MAX_RESPONSES, MAX_TEXT, parse, read};
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

fuzz_target!(|data: &[u8]| {
    let parsed = parse(data);
    let mut streamed = Vec::new();
    let read = pin!(read(data, |r| {
        streamed.push(r);
        Ok(())
    }))
    .poll(&mut Context::from_waker(Waker::noop()));
    let Poll::Ready(read) = read else { panic!("a slice never waits") };
    assert_eq!(parsed.as_ref().ok(), read.map(|()| streamed).as_ref().ok());
    let Ok(all) = parsed else { return };
    assert!(all.len() <= MAX_RESPONSES);
    for r in all {
        assert!(r.path.len() <= MAX_HREF && r.path.first() == Some(&b'/') && !r.path.contains(&0));
        assert!(r.props.etag.len() <= MAX_TEXT && r.props.content_type.len() <= MAX_TEXT);
    }
});
