// SPDX-License-Identifier: LGPL-2.1-or-later
//! Pins sspi's NTLMv2 client against MS-NLMP 4.2.4 (NTLMv2 authentication example).
//!
//! sspi draws the client challenge and exported session key from the OS RNG and takes the time from the server's MsvAvTimestamp (or the clock), with no way to inject the 4.2.4 values, so the published NTProofStr cannot be replayed byte for byte. Instead the 4.2.4 *inputs* (User/Domain/Password, server challenge 0123456789abcdef, flags 0xE28A8233, target info Domain/Server) go into sspi, and its AUTHENTICATE_MESSAGE is checked with the published NTOWFv2 value and RustCrypto primitives (test-only): NTProofStr, LMv2, KeyExchangeKey → exported session key, MIC.
//!
//! Published values (MS-NLMP 4.2.4.1.1, 4.2.4.1.2, 4.2.4.2.1, 4.2.4.2.2), as transcribed in pyspnego `tests/_ntlm_raw/test_crypto.py` <https://raw.githubusercontent.com/jborean93/pyspnego/main/tests/_ntlm_raw/test_crypto.py>.
#![allow(clippy::doc_markdown)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use rc4::{Rc4, StreamCipher};
use sspi::ntlm::NtlmConfig;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm, SecurityBuffer,
    SecurityStatus, Sspi, SspiImpl, Username,
};

/// NTOWFv2("Password", "User", "Domain"), MS-NLMP 4.2.4.1.1.
const NTOWFV2: [u8; 16] = hex16("0c868a403bfd7a93a3001ef22ef02e3f");
const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// NTLMSSP_NEGOTIATE_{KEY_EXCH,56,128,VERSION,TARGET_INFO,EXTENDED_SESSIONSECURITY,
/// TARGET_TYPE_SERVER,ALWAYS_SIGN,NTLM,SEAL,SIGN,OEM,UNICODE} (MS-NLMP 4.2.4).
const FLAGS: u32 = 0xE28A_8233;
const KEY_EXCH: u32 = 0x4000_0000;
const MIC_OFFSET: usize = 72;

const fn hex16(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <Hmac<Md5> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn av(id: u16, value: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    v.extend_from_slice(value);
    v
}

/// The 4.2.4.3 CHALLENGE_MESSAGE layout, optionally with an MsvAvTimestamp.
fn challenge(timestamp: Option<u64>) -> Vec<u8> {
    let name = utf16("Server");
    let mut info = av(2, &utf16("Domain"));
    info.extend(av(1, &utf16("Server")));
    if let Some(t) = timestamp {
        info.extend(av(7, &t.to_le_bytes()));
    }
    info.extend(av(0, &[]));
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend_from_slice(&2u32.to_le_bytes());
    let name_off = 56u32;
    m.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&name_off.to_le_bytes());
    m.extend_from_slice(&FLAGS.to_le_bytes());
    m.extend_from_slice(&SERVER_CHALLENGE);
    m.extend_from_slice(&[0; 8]);
    let info_off = name_off + u32::try_from(name.len()).unwrap();
    m.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&info_off.to_le_bytes());
    m.extend_from_slice(&[0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f]); // Version
    assert_eq!(m.len(), 56);
    m.extend(name);
    m.extend(info);
    m
}

struct Run {
    negotiate: Vec<u8>,
    challenge: Vec<u8>,
    authenticate: Vec<u8>,
    exported_key: Vec<u8>,
}

fn run_sspi(timestamp: Option<u64>) -> Run {
    let mut ntlm = Ntlm::with_config(NtlmConfig::default());
    let identity = AuthIdentity {
        username: Username::new("User", Some("Domain")).unwrap(),
        password: "Password".to_owned().into(),
    };
    let mut creds = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Outbound)
        .with_auth_data(&identity)
        .execute(&mut ntlm)
        .unwrap()
        .credentials_handle;
    let flags = ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::CONFIDENTIALITY
        | ClientRequestFlags::ALLOCATE_MEMORY;
    let mut step = |ntlm: &mut Ntlm, input: Option<Vec<u8>>| -> (SecurityStatus, Vec<u8>) {
        let mut out = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut inp = input.map(|t| vec![SecurityBuffer::new(t, BufferType::Token)]);
        let mut b = ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut creds)
            .with_context_requirements(flags)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("cifs/Server")
            .with_output(&mut out);
        if let Some(i) = inp.as_mut() {
            b = b.with_input(i);
        }
        let r = <Ntlm as SspiImpl>::initialize_security_context_impl(ntlm, &mut b)
            .unwrap()
            .resolve_to_result()
            .unwrap();
        (r.status, out.remove(0).buffer)
    };
    let (s1, negotiate) = step(&mut ntlm, None);
    assert_eq!(s1, SecurityStatus::ContinueNeeded);
    let chal = challenge(timestamp);
    let (s2, authenticate) = step(&mut ntlm, Some(chal.clone()));
    assert_eq!(s2, SecurityStatus::Ok);
    let exported_key = ntlm.query_context_session_key().unwrap().session_key.as_ref().clone();
    Run { negotiate, challenge: chal, authenticate, exported_key }
}

fn field(msg: &[u8], at: usize) -> &[u8] {
    let len = usize::from(u16::from_le_bytes([msg[at], msg[at + 1]]));
    let off = u32::from_le_bytes(msg[at + 4..at + 8].try_into().unwrap()) as usize;
    &msg[off..off + len]
}

fn av_pairs(mut b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let id = u16::from_le_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_le_bytes([b[2], b[3]]));
        out.push((id, b[4..4 + len].to_vec()));
        if id == 0 {
            break;
        }
        b = &b[4 + len..];
    }
    out
}

#[test]
fn published_values_check_the_test_helpers() {
    // LMv2 with ClientChallenge aa*8: MS-NLMP 4.2.4.2.1.
    let lm = hmac_md5(&NTOWFV2, &[&SERVER_CHALLENGE, &[0xaa; 8]]);
    assert_eq!(lm, hex16("86c35097ac9cec102554764a57cccc19"));
    // SessionBaseKey = KeyExchangeKey from NTProofStr: MS-NLMP 4.2.4.1.2.
    let kek = hmac_md5(&NTOWFV2, &[&hex16("68cd0ab851e51c96aabc927bebef6a1c")]);
    assert_eq!(kek, hex16("8de40ccadbc14a82f15cb0ad0de95ca3"));
    // RC4(KeyExchangeKey, RandomSessionKey 55*16): MS-NLMP 4.2.4.2.3.
    let mut k = [0x55u8; 16];
    Rc4::new_from_slice(&kek).unwrap().apply_keystream(&mut k);
    assert_eq!(k, hex16("c5dad2544fc9799094ce1ce90bc9d03e"));
}

#[test]
fn sspi_ntlmv2_matches_ms_nlmp_4_2_4() {
    let r = run_sspi(None);
    let a = &r.authenticate;
    assert_eq!(&a[..12], b"NTLMSSP\0\x03\0\0\0");
    let flags = u32::from_le_bytes(a[60..64].try_into().unwrap());
    assert_ne!(flags & KEY_EXCH, 0, "KEY_EXCH negotiated");
    assert_eq!(field(a, 28), utf16("Domain"));
    assert_eq!(field(a, 36), utf16("User"));
    assert!(field(a, 44).is_empty(), "no workstation name is sent");

    // NTLMv2 response: NTProofStr ‖ blob, NTProofStr = HMAC-MD5(NTOWFv2, SC ‖ blob).
    let nt = field(a, 20);
    let (proof, blob) = nt.split_at(16);
    assert_eq!(proof, hmac_md5(&NTOWFV2, &[&SERVER_CHALLENGE, blob]));
    assert_eq!(&blob[..2], &[1, 1]);
    let client_challenge = &blob[16..24];
    // LMv2 = HMAC-MD5(NTOWFv2, SC ‖ CC) ‖ CC (sent although MS-NLMP 3.1.5.1.2 says SHOULD NOT when the server sends MsvAvTimestamp; here it does not).
    let mut lm = hmac_md5(&NTOWFV2, &[&SERVER_CHALLENGE, client_challenge]).to_vec();
    lm.extend_from_slice(client_challenge);
    assert_eq!(field(a, 12), lm);

    // Exported session key = RC4(KeyExchangeKey, EncryptedRandomSessionKey), and it is what
    // sspi hands out (the SMB key derivation input).
    let kek = hmac_md5(&NTOWFV2, &[proof]);
    let mut exported: [u8; 16] = field(a, 52).try_into().unwrap();
    Rc4::new_from_slice(&kek).unwrap().apply_keystream(&mut exported);
    assert_eq!(r.exported_key, exported);
    assert_ne!(exported, kek, "a random session key, not the key exchange key");

    // MIC = HMAC-MD5(ExportedSessionKey, NEGOTIATE ‖ CHALLENGE ‖ AUTHENTICATE with MIC zeroed).
    let mut zeroed = a.clone();
    zeroed[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
    let mic = hmac_md5(&exported, &[&r.negotiate, &r.challenge, &zeroed]);
    assert_eq!(&a[MIC_OFFSET..MIC_OFFSET + 16], mic);

    // Target info echoed in the blob: the server's pairs, MsvAvFlags with "MIC present" (0x2),
    // a timestamp from the clock (none from the server), and NO MsvAvTargetName (SPN) and no
    // channel bindings although a target name was given.
    let pairs = av_pairs(&blob[28..]);
    let ids: Vec<u16> = pairs.iter().map(|p| p.0).collect();
    assert_eq!(ids, vec![2, 1, 6, 0], "{ids:?}");
    assert_eq!(pairs[2].1, 2u32.to_le_bytes());
    assert_ne!(&blob[8..16], &[0; 8], "time from the client clock");
}

#[test]
fn sspi_uses_the_servers_timestamp() {
    let r = run_sspi(Some(0x01d0_0000_0000_0000));
    let nt = field(&r.authenticate, 20);
    assert_eq!(&nt[16 + 8..16 + 16], &0x01d0_0000_0000_0000u64.to_le_bytes());
    // LMv2 is still sent (not Z(24)).
    assert_ne!(field(&r.authenticate, 12), &[0u8; 24][..]);
}
