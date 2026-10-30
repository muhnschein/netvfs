// SPDX-License-Identifier: LGPL-2.1-or-later
//! SPNEGO tokens raw: first SESSION_SETUP response and the final one after a well-formed challenge. No panic; final token accepted only with a valid MIC.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_smb::auth::{Account, Authenticator, Step};
use zeroize::Zeroizing;

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        out.extend_from_slice(&[0x81, len as u8]);
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn av(id: u16, value: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(value.len() as u16).to_le_bytes());
    v.extend_from_slice(value);
    v
}

/// MS-NLMP 4.2.4.3 CHALLENGE_MESSAGE in a NegTokenResp.
fn challenge() -> Vec<u8> {
    const FLAGS: u32 = 0xe28a_8233;
    let name = utf16("Server");
    let mut info = av(2, &utf16("Domain"));
    info.extend(av(1, &utf16("Server")));
    info.extend(av(0, &[]));
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend_from_slice(&2u32.to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&56u32.to_le_bytes());
    m.extend_from_slice(&FLAGS.to_le_bytes());
    m.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    m.extend_from_slice(&[0; 8]);
    m.extend_from_slice(&(info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(56 + name.len() as u32).to_le_bytes());
    m.extend_from_slice(&[0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f]);
    m.extend(name);
    m.extend(info);
    const NTLMSSP_OID: [u8; 12] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let mut fields = tlv(0xa0, &[0x0a, 0x01, 0x01]);
    fields.extend(tlv(0xa1, &NTLMSSP_OID));
    fields.extend(tlv(0xa2, &tlv(0x04, &m)));
    tlv(0xa1, &tlv(0x30, &fields))
}

fn account() -> Account {
    Account::User { user: "User".into(), domain: "Domain".into(), password: Zeroizing::new("Password".into()) }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 60_000 {
        return;
    }
    let (mut first, _) = Authenticator::start(&account(), "srv").unwrap();
    let _ = first.step(data);

    let (mut auth, _) = Authenticator::start(&account(), "srv").unwrap();
    let Ok(Step::Continue(_)) = auth.step(&challenge()) else {
        panic!("the well-formed challenge was refused");
    };
    assert!(auth.finish(data).is_err(), "a final token without a valid mechListMIC was accepted");
});
