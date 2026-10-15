// SPDX-License-Identifier: LGPL-2.1-or-later
//! The srvsvc share list (XM-7) as the server's pipe gives it: DCE/RPC
//! fragments of any size, reassembled, then the NetrShareEnum level 1 stub
//! decoded; the input is also taken as one stub and as a bind_ack. None may
//! panic, and what is accepted obeys the caps (count, remark length), holds
//! valid share names only and no control characters in the remarks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_smb::names::valid_share_name;
use netvfs_smb::rpc::{MAX_REMARK, MAX_SHARES, MAX_STUB, Reassembly, ShareInfo, check_bind_ack, decode_share_enum};

fn check(shares: &[ShareInfo]) {
    assert!(shares.len() <= MAX_SHARES);
    for share in shares {
        assert!(valid_share_name(&share.name), "{:?}", share.name);
        assert!(share.remark.chars().count() <= MAX_REMARK);
        assert!(!share.remark.chars().any(char::is_control));
        let _ = share.visible(false);
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = check_bind_ack(data);
    if let Ok(shares) = decode_share_enum(data) {
        check(&shares);
    }
    // The first byte sets the piece size the pipe hands over.
    let Some((&piece, pipe)) = data.split_first() else { return };
    let mut reply = Reassembly::new();
    for chunk in pipe.chunks(usize::from(piece).max(1)) {
        if reply.feed(chunk).is_err() {
            return;
        }
        assert!(reply.stub().len() <= MAX_STUB);
    }
    if reply.done() {
        if let Ok(shares) = decode_share_enum(reply.stub()) {
            check(&shares);
        }
    }
});
