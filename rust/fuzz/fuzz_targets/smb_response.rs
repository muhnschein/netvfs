// SPDX-License-Identifier: LGPL-2.1-or-later
//! What an SMB server sends, once it is out of its frame (and transform):
//! a chain of SMB2 messages, each decoded by every response decoder of
//! netvfs-smb. None may panic, and what they accept obeys their caps.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_smb::crypto::Cipher;
use netvfs_smb::msg::file::{
    Created, check_close_response, check_flush_response, check_set_info_response, fs_full_size_response,
    ioctl_response, parse_id_both_directory, query_directory_response, read_response, write_response,
};
use netvfs_smb::msg::negotiate::NegotiateResponse;
use netvfs_smb::msg::session::{SetupResponse, check_four_byte_response};
use netvfs_smb::msg::tree::TreeConnectResponse;
use netvfs_smb::msg::{Header, check_error_response, split_chain};
use netvfs_smb::names::wtf8_from_utf16;
use netvfs_smb::negotiate::{Offer, check_response};

const LIMIT: usize = 65_536;

fuzz_target!(|data: &[u8]| {
    let Ok(ranges) = split_chain(data) else { return };
    for range in ranges {
        let Some(msg) = data.get(range) else { panic!("a chain range outside the frame") };
        if Header::decode(msg).is_err() {
            continue;
        }
        let _ = check_error_response(msg);
        if let Ok(resp) = NegotiateResponse::decode(msg) {
            let offer = Offer::new(true, vec![Cipher::Aes128Gcm, Cipher::Aes256Gcm]).unwrap();
            if let Ok(n) = check_response(&offer, &resp) {
                assert_eq!(n.dialect, 0x0311);
            }
        }
        let _ = SetupResponse::decode(msg);
        let _ = TreeConnectResponse::decode(msg);
        let _ = Created::decode(msg);
        if let Ok(read) = read_response(msg, LIMIT) {
            assert!(read.len() <= LIMIT);
        }
        if let Ok(written) = write_response(msg, LIMIT) {
            assert!(written <= LIMIT);
        }
        if let Ok(out) = ioctl_response(msg, LIMIT) {
            assert!(out.len() <= LIMIT);
        }
        if let Ok(entries) = query_directory_response(msg, LIMIT) {
            for e in entries {
                let _ = wtf8_from_utf16(&e.name);
            }
        }
        let _ = parse_id_both_directory(msg);
        let _ = fs_full_size_response(msg);
        let _ = check_close_response(msg);
        let _ = check_flush_response(msg);
        let _ = check_set_info_response(msg);
        let _ = check_four_byte_response(msg, "ECHO");
    }
});
