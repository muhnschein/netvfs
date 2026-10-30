// SPDX-License-Identifier: LGPL-2.1-or-later
//! NTLM CHALLENGE_MESSAGE in a SPNEGO NegTokenResp (NTLMv2) and raw (anonymous). No panic; accepted challenge gives AUTHENTICATE token.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_smb::auth::{Account, Authenticator, Step};
use zeroize::Zeroizing;

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

fn neg_token_resp(token: &[u8]) -> Vec<u8> {
    const NTLMSSP_OID: [u8; 12] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let mut fields = tlv(0xa0, &[0x0a, 0x01, 0x01]);
    fields.extend(tlv(0xa1, &NTLMSSP_OID));
    fields.extend(tlv(0xa2, &tlv(0x04, token)));
    tlv(0xa1, &tlv(0x30, &fields))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 60_000 {
        return;
    }
    let account = Account::User {
        user: "User".into(),
        domain: "Domain".into(),
        password: Zeroizing::new("Password".into()),
    };
    let (mut ntlm, first) = Authenticator::start(&account, "srv").unwrap();
    assert!(!first.is_empty());
    if let Ok(Step::Continue(token)) = ntlm.step(&neg_token_resp(data)) {
        assert!(!token.is_empty());
    }

    let (mut anonymous, _) = Authenticator::start(&Account::Anonymous, "srv").unwrap();
    if let Ok(Step::Continue(token)) = anonymous.step(data) {
        assert!(token.starts_with(b"NTLMSSP\0"));
        assert!(anonymous.session_key().is_err());
    }
});
