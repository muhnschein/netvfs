// SPDX-License-Identifier: LGPL-2.1-or-later
//! Known-answer and bit-flip tests for the crypto glue.
//!
//! Vector provenance (the constants at the end were generated mechanically from these files,
//! not typed; a transcription error would make a test fail, not pass):
//! - Microsoft Open Specifications blog, "SMB 3.1.1 Pre-authentication integrity in Windows 10"
//!   <https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-pre-authentication-integrity-in-windows-10>,
//!   as transcribed in Dell's pike, `tests/test_smb3_encryption_vector.py`
//!   <https://raw.githubusercontent.com/dell/pike/master/tests/test_smb3_encryption_vector.py>
//!   (constants `PIKE_PA_*`).
//! - Microsoft Open Specifications blog, "SMB 3.1.1 Encryption in Windows 10", Appendix A.1
//!   (AES-128-GCM) and A.2 (AES-128-CCM; only its keys and its AES-CMAC-signed final
//!   SESSION_SETUP response are used here)
//!   <https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-encryption-in-windows-10>,
//!   as transcribed in `packages/smb2/test/fixtures/smb3-vectors.ts` of sanjay3290/winlinux
//!   <https://raw.githubusercontent.com/sanjay3290/winlinux/main/packages/smb2/test/fixtures/smb3-vectors.ts>
//!   (constants `BLOG_GCM_*`, `BLOG_CCM_*`). The A.1 WRITE vector also appears byte for byte
//!   in pike and in cryptomator/jsmb `MessageEncryptorTest.java`.
//! - Microsoft Open Specifications blog, "Encryption in SMB 3.0: A protocol perspective"
//!   <https://learn.microsoft.com/en-us/archive/blogs/openspecification/encryption-in-smb-3-0-a-protocol-perspective>,
//!   same transcriptions (constants `BLOG_SMB30_*`): exercises the KDF with other labels.
//! - Not Microsoft-published, third party: Wireshark's decryption test captures
//!   `test/captures/smb311-aes-128-gcm.pcap.gz` and `smb311-aes-256-gcm.pcap.gz` with the
//!   session keys from `test/suite_decryption.py`
//!   <https://gitlab.com/wireshark/wireshark/-/raw/master/test/suite_decryption.py>
//!   (constants `WS128_*`, `WS256_*`, one SMB2 message per frame). The only AES-256-GCM
//!   vector found: no Microsoft publication with one was reachable.

use super::{
    Cipher, CryptoError, GcmKey, LABEL_SIGNING, OpenKey, PreauthHash, SealKey, SigningKey,
    TRANSFORM_HEADER_LEN, derive_session_keys, kdf,
};
use zeroize::Zeroizing;

fn hex(parts: &[&str]) -> Vec<u8> {
    let s: String = parts.concat();
    assert!(s.len().is_multiple_of(2));
    s.as_bytes().chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
}

fn arr<const N: usize>(parts: &[&str]) -> [u8; N] {
    hex(parts).try_into().unwrap()
}

fn flip(buf: &[u8], bit: usize) -> Vec<u8> {
    let mut v = buf.to_vec();
    v[bit / 8] ^= 1 << (bit % 8);
    v
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Raw key bytes of a seal key (tests only).
fn seal_key_bytes(k: &SealKey) -> Vec<u8> {
    match &k.key {
        GcmKey::Aes128(b) => b.to_vec(),
        GcmKey::Aes256(b) => b.to_vec(),
    }
}

fn open_key_bytes(k: &OpenKey) -> Vec<u8> {
    match &k.key {
        GcmKey::Aes128(b) => b.to_vec(),
        GcmKey::Aes256(b) => b.to_vec(),
    }
}

fn open_key_128(key: [u8; 16], session_id: u64) -> OpenKey {
    OpenKey { key: GcmKey::Aes128(Zeroizing::new(key)), session_id }
}

fn seal_key_128(key: [u8; 16], session_id: u64) -> SealKey {
    SealKey { key: GcmKey::Aes128(Zeroizing::new(key)), session_id, counter: 0, salt: [0; 4] }
}

// ---------------------------------------------------------------------------------------------
// Microsoft-published vectors
// ---------------------------------------------------------------------------------------------

#[test]
fn preauth_chain_and_signing_key_match_preauth_blog() {
    let mut h = PreauthHash::default();
    for (msg, want) in [
        (PIKE_PA_NEGOTIATE_REQUEST, PIKE_PA_EXP_PAE_1),
        (PIKE_PA_NEGOTIATE_RESPONSE, PIKE_PA_EXP_PAE_2),
        (PIKE_PA_SESSION_SETUP_REQUEST, PIKE_PA_EXP_PAE_3),
        (PIKE_PA_SESSION_SETUP_RESPONSE, PIKE_PA_EXP_PAE_4),
        // pike calls the second SESSION_SETUP *request* "response2" (MessageId 3, no
        // SERVER_TO_REDIR flag): the chain ends with the last request.
        (PIKE_PA_SESSION_SETUP_RESPONSE2, PIKE_PA_EXP_PAE_5),
    ] {
        h.update(&hex(msg));
        assert_eq!(h.value()[..], hex(want)[..]);
    }
    let signing = kdf::<16>(&hex(PIKE_PA_SESSION_KEY), LABEL_SIGNING, h.value()).unwrap();
    assert_eq!(signing[..], hex(PIKE_PA_EXP_SIGNING_KEY)[..]);
}

#[test]
fn preauth_chain_matches_encryption_blog_a1() {
    let mut h = PreauthHash::default();
    for (msg, want) in [
        (BLOG_GCM_NEGOTIATE_REQUEST, BLOG_GCM_HASH_AFTER_NEGOTIATE_REQUEST),
        (BLOG_GCM_NEGOTIATE_RESPONSE, BLOG_GCM_HASH_AFTER_NEGOTIATE_RESPONSE),
        (BLOG_GCM_SETUP_REQUEST1, BLOG_GCM_HASH_AFTER_SETUP_REQUEST1),
        (BLOG_GCM_SETUP_RESPONSE1, BLOG_GCM_HASH_AFTER_SETUP_RESPONSE1),
        (BLOG_GCM_SETUP_REQUEST2, BLOG_GCM_HASH_AFTER_SETUP_REQUEST2),
    ] {
        h.update(&hex(msg));
        assert_eq!(h.value()[..], hex(want)[..]);
    }
    // The same final value as pike's independent transcription of this appendix.
    assert_eq!(
        h.value()[..],
        hex(&[
            "B23F3CBFD69487D9832B79B1594A367CDD950909B774C3A4C412B4FCEA9EDDDBA7DB256BA2EA30E9",
            "77F11F9B113247578E0E915C6D2A513B8F2FCA5707DC8770"
        ])[..]
    );
}

fn blog_a1_hash() -> PreauthHash {
    let mut h = PreauthHash::default();
    for m in [
        BLOG_GCM_NEGOTIATE_REQUEST,
        BLOG_GCM_NEGOTIATE_RESPONSE,
        BLOG_GCM_SETUP_REQUEST1,
        BLOG_GCM_SETUP_RESPONSE1,
        BLOG_GCM_SETUP_REQUEST2,
    ] {
        h.update(&hex(m));
    }
    h
}

/// SessionId of the A.1 session (from its headers).
const BLOG_A1_SESSION: u64 = 0x0000_1000_0000_0025;

#[test]
fn session_keys_match_encryption_blog_a1() {
    let keys = derive_session_keys(
        &hex(BLOG_GCM_SESSION_KEY),
        &blog_a1_hash(),
        Some(Cipher::Aes128Gcm),
        BLOG_A1_SESSION,
    )
    .unwrap();
    assert_eq!(keys.signing.0[..], hex(BLOG_GCM_SIGNING_KEY)[..]);
    assert_eq!(seal_key_bytes(keys.seal.as_ref().unwrap()), hex(BLOG_GCM_ENCRYPTION_KEY));
    assert_eq!(open_key_bytes(keys.open.as_ref().unwrap()), hex(BLOG_GCM_DECRYPTION_KEY));
    // The derived signing key verifies the server's signed final SESSION_SETUP response.
    keys.signing.verify(&hex(BLOG_GCM_SETUP_RESPONSE2)).unwrap();
}

#[test]
fn cmac_signature_matches_encryption_blog_a1() {
    let key = SigningKey::from_bytes(arr(BLOG_GCM_SIGNING_KEY));
    let signed = hex(BLOG_GCM_SETUP_RESPONSE2);
    key.verify(&signed).unwrap();
    // Signing the same message (signature field cleared) reproduces the signature.
    let mut msg = signed.clone();
    msg[48..64].fill(0);
    key.sign(&mut msg).unwrap();
    assert_eq!(msg, signed);
}

#[test]
fn keys_and_cmac_signature_match_encryption_blog_a2() {
    let hash = PreauthHash(arr(BLOG_CCM_HASH_AFTER_SETUP_REQUEST2));
    let sk = hex(BLOG_CCM_SESSION_KEY);
    assert_eq!(kdf::<16>(&sk, LABEL_SIGNING, hash.value()).unwrap()[..], hex(BLOG_CCM_SIGNING_KEY)[..]);
    assert_eq!(
        kdf::<16>(&sk, super::LABEL_C2S_CIPHER, hash.value()).unwrap()[..],
        hex(BLOG_CCM_ENCRYPTION_KEY)[..]
    );
    assert_eq!(
        kdf::<16>(&sk, super::LABEL_S2C_CIPHER, hash.value()).unwrap()[..],
        hex(BLOG_CCM_DECRYPTION_KEY)[..]
    );
    // CCM is never negotiated by us, but this session signs with AES-CMAC too.
    SigningKey::from_bytes(arr(BLOG_CCM_SIGNING_KEY)).verify(&hex(BLOG_CCM_SETUP_RESPONSE2)).unwrap();
}

#[test]
fn gcm_seal_matches_encryption_blog_a1() {
    let key = seal_key_128(arr(BLOG_GCM_ENCRYPTION_KEY), BLOG_A1_SESSION);
    let sealed = key.seal_with_nonce(&arr(BLOG_GCM_WRITE_NONCE), &hex(BLOG_GCM_WRITE_PLAIN)).unwrap();
    assert_eq!(sealed, hex(BLOG_GCM_WRITE_TRANSFORMED));
}

#[test]
fn gcm_open_matches_encryption_blog_a1() {
    let key = open_key_128(arr(BLOG_GCM_DECRYPTION_KEY), BLOG_A1_SESSION);
    assert_eq!(key.open(&hex(BLOG_GCM_RESPONSE_TRANSFORMED)).unwrap(), hex(BLOG_GCM_RESPONSE_PLAIN));
    // And the request direction, opened with the client-to-server key.
    let c2s = open_key_128(arr(BLOG_GCM_ENCRYPTION_KEY), BLOG_A1_SESSION);
    assert_eq!(c2s.open(&hex(BLOG_GCM_WRITE_TRANSFORMED)).unwrap(), hex(BLOG_GCM_WRITE_PLAIN));
}

#[test]
fn kdf_matches_smb30_blog() {
    // SMB 3.0 uses constant labels and contexts instead of the preauth hash; the KDF is the
    // same function, so these pin label/context handling (NUL terminators included).
    let sk = hex(BLOG_SMB30_SESSION_KEY);
    assert_eq!(kdf::<16>(&sk, b"SMB2AESCMAC\0", b"SmbSign\0").unwrap()[..], hex(BLOG_SMB30_SIGNING_KEY)[..]);
    assert_eq!(
        kdf::<16>(&sk, b"SMB2AESCCM\0", b"ServerIn \0").unwrap()[..],
        hex(BLOG_SMB30_ENCRYPTION_KEY)[..]
    );
    assert_eq!(
        kdf::<16>(&sk, b"SMB2AESCCM\0", b"ServerOut\0").unwrap()[..],
        hex(BLOG_SMB30_DECRYPTION_KEY)[..]
    );
}

// ---------------------------------------------------------------------------------------------
// Third-party vectors: Wireshark captures (real traffic, keys from Wireshark's test suite)
// ---------------------------------------------------------------------------------------------

fn capture_hash(frames: [&[&str]; 5]) -> PreauthHash {
    let mut h = PreauthHash::default();
    for f in frames {
        h.update(&hex(f));
    }
    h
}

#[test]
fn wireshark_aes128gcm_capture() {
    // suite_decryption.py: sesid 3900000000400000, seskey e79161de..., s2c b02f5de2..., c2s 7201623a...
    let session = u64::from_le_bytes(arr(&["3900000000400000"]));
    let hash = capture_hash([WS128_FRAME1, WS128_FRAME2, WS128_FRAME3, WS128_FRAME4, WS128_FRAME5]);
    let keys = derive_session_keys(
        &hex(&["e79161ded03bda1449b2c8e58f753953"]),
        &hash,
        Some(Cipher::Aes128Gcm),
        session,
    )
    .unwrap();
    assert_eq!(open_key_bytes(keys.open.as_ref().unwrap()), hex(&["b02f5de25e0562075c3dc329fa2aa396"]));
    assert_eq!(seal_key_bytes(keys.seal.as_ref().unwrap()), hex(&["7201623a31754e6581864581209dd3d2"]));
    // The final SESSION_SETUP response (frame 6) is AES-CMAC signed (no signing context
    // was negotiated in this capture, so CMAC is the 3.1.1 default).
    keys.signing.verify(&hex(WS128_FRAME6)).unwrap();
    // Frame 8: encrypted TREE_CONNECT response.
    let resp = keys.open.as_ref().unwrap().open(&hex(WS128_FRAME8)).unwrap();
    assert_eq!(&resp[..4], b"\xfeSMB");
    assert_eq!(u16::from_le_bytes([resp[12], resp[13]]), 3);
    // Frame 7: encrypted TREE_CONNECT request, opened with the client-to-server key.
    let c2s = open_key_128(seal_key_bytes(keys.seal.as_ref().unwrap()).try_into().unwrap(), session);
    let req = c2s.open(&hex(WS128_FRAME7)).unwrap();
    assert!(contains(&req, &utf16(r"\\dfsroot1.foo.test\IPC$")));
}

#[test]
fn wireshark_aes256gcm_capture() {
    // suite_decryption.py: sesid 56dc03ab00000000, seskey 6a5004ad... (16 bytes, NTLM),
    // s2c 46b64f32... and c2s 484c30bf... (32 bytes each): the 256-bit keys come from the
    // 16-byte full session key with L = 256.
    let session = u64::from_le_bytes(arr(&["56dc03ab00000000"]));
    let hash = capture_hash([WS256_FRAME1, WS256_FRAME2, WS256_FRAME3, WS256_FRAME4, WS256_FRAME5]);
    let keys = derive_session_keys(
        &hex(&["6a5004adfbdef1abd5879800675324e5"]),
        &hash,
        Some(Cipher::Aes256Gcm),
        session,
    )
    .unwrap();
    // Wireshark's UAT for this capture lists 46b64f32... as "s2c" and 484c30bf... as "c2s",
    // but its suite also passes them swapped (test_smb311_aes256gcm_partial_keyswap: the
    // dissector tries both). What decides is which key opens which direction (below): the
    // MS-SMB2 labels give S2C = 484c30bf... and C2S = 46b64f32..., and those decrypt the
    // server's and the client's frame respectively.
    assert_eq!(
        open_key_bytes(keys.open.as_ref().unwrap()),
        hex(&["484c30bf3e17e322e0d217764d4584a325ec0495519c3f1547e0f996ab76c4c4"])
    );
    assert_eq!(
        seal_key_bytes(keys.seal.as_ref().unwrap()),
        hex(&["46b64f320a0f856b63b3a0dc2c058a67267830a8cbdd44a088fbf1d0308a981f"])
    );
    assert_eq!(keys.seal.as_ref().unwrap().cipher(), Cipher::Aes256Gcm);
    let resp = keys.open.as_ref().unwrap().open(&hex(WS256_FRAME8)).unwrap();
    assert_eq!(&resp[..4], b"\xfeSMB");
    assert_eq!(u16::from_le_bytes([resp[12], resp[13]]), 3);
    let c2s = OpenKey::from_bytes(Cipher::Aes256Gcm, &seal_key_bytes(keys.seal.as_ref().unwrap()), session)
        .unwrap();
    let req = c2s.open(&hex(WS256_FRAME7)).unwrap();
    assert!(contains(&req, &utf16(r"\\172.31.9.163\IPC$")));
    // This capture negotiated AES-GMAC signing (signing context 0x0008, algorithm 2), which
    // we never offer: its frame 6 must NOT verify as AES-CMAC.
    assert_eq!(keys.signing.verify(&hex(WS256_FRAME6)), Err(CryptoError::BadSignature));
}

// ---------------------------------------------------------------------------------------------
// Bit flips: every altered input must fail
// ---------------------------------------------------------------------------------------------

#[test]
fn cmac_any_flipped_bit_fails() {
    let key: [u8; 16] = arr(BLOG_GCM_SIGNING_KEY);
    let msg = hex(BLOG_GCM_SETUP_RESPONSE2);
    SigningKey::from_bytes(key).verify(&msg).unwrap();
    for bit in 0..128 {
        let k: [u8; 16] = flip(&key, bit).try_into().unwrap();
        assert_eq!(SigningKey::from_bytes(k).verify(&msg), Err(CryptoError::BadSignature), "key bit {bit}");
    }
    for bit in 0..msg.len() * 8 {
        // Signature bits (48..64) and every other header/body bit.
        assert_eq!(
            SigningKey::from_bytes(key).verify(&flip(&msg, bit)),
            Err(CryptoError::BadSignature),
            "message bit {bit}"
        );
    }
    // Truncated or extended messages fail too.
    SigningKey::from_bytes(key).verify(&msg[..msg.len() - 1]).unwrap_err();
    let mut longer = msg.clone();
    longer.push(0);
    SigningKey::from_bytes(key).verify(&longer).unwrap_err();
    assert_eq!(SigningKey::from_bytes(key).verify(&msg[..63]), Err(CryptoError::ShortMessage));
}

#[test]
fn gcm_any_flipped_bit_fails() {
    let key: [u8; 16] = arr(BLOG_GCM_DECRYPTION_KEY);
    let frame = hex(BLOG_GCM_RESPONSE_TRANSFORMED);
    open_key_128(key, BLOG_A1_SESSION).open(&frame).unwrap();
    for bit in 0..128 {
        let k: [u8; 16] = flip(&key, bit).try_into().unwrap();
        assert_eq!(
            open_key_128(k, BLOG_A1_SESSION).open(&frame),
            Err(CryptoError::Unauthentic),
            "key bit {bit}"
        );
    }
    for bit in 0..frame.len() * 8 {
        let byte = bit / 8;
        let got = open_key_128(key, BLOG_A1_SESSION).open(&flip(&frame, bit));
        let want = match byte {
            0..4 => Err(CryptoError::Malformed("not a transform header")),
            // tag 4..20, nonce 20..32, unused nonce bytes 32..36, Reserved 40..42, ciphertext
            4..36 | 40..42 | 52.. => Err(CryptoError::Unauthentic),
            36..40 => Err(CryptoError::Malformed("OriginalMessageSize does not match the frame")),
            42..44 => Err(CryptoError::Malformed("flags are not 'encrypted'")),
            44..52 => Err(CryptoError::WrongSession),
        };
        assert_eq!(got, want, "frame bit {bit}");
    }
}

#[test]
fn gcm_aad_is_bytes_20_to_52_only_and_checked_by_the_tag() {
    // With the field checks out of the way (same session, size, flags), every AAD byte still
    // has to be authenticated: re-seal with the session id changed and open with a key that
    // expects the old id -> WrongSession; open with the matching id -> fine.
    let key = seal_key_128(arr(BLOG_GCM_ENCRYPTION_KEY), BLOG_A1_SESSION + 1);
    let sealed = key.seal_with_nonce(&arr(BLOG_GCM_WRITE_NONCE), &hex(BLOG_GCM_WRITE_PLAIN)).unwrap();
    assert_ne!(sealed[4..20], hex(BLOG_GCM_WRITE_TRANSFORMED)[4..20], "session id is in the AAD");
    assert_eq!(
        open_key_128(arr(BLOG_GCM_ENCRYPTION_KEY), BLOG_A1_SESSION).open(&sealed),
        Err(CryptoError::WrongSession)
    );
    open_key_128(arr(BLOG_GCM_ENCRYPTION_KEY), BLOG_A1_SESSION + 1).open(&sealed).unwrap();
}

#[test]
fn open_refuses_malformed_frames() {
    let key = open_key_128([7; 16], 1);
    assert_eq!(key.open(&[]), Err(CryptoError::Malformed("short frame")));
    assert_eq!(key.open(&[0xFD; TRANSFORM_HEADER_LEN - 1]), Err(CryptoError::Malformed("short frame")));
    let mut frame = seal_key_128([7; 16], 1).seal(b"hello").unwrap();
    key.open(&frame).unwrap();
    frame.push(0);
    assert_eq!(key.open(&frame), Err(CryptoError::Malformed("OriginalMessageSize does not match the frame")));
    frame.pop();
    frame[42] = 0; // flags 0
    assert_eq!(key.open(&frame), Err(CryptoError::Malformed("flags are not 'encrypted'")));
    frame[0] = 0xFE; // a plain SMB2 header is not a transform
    assert_eq!(key.open(&frame), Err(CryptoError::Malformed("not a transform header")));
}

#[test]
fn kdf_inputs_all_matter() {
    let sk = hex(BLOG_SMB30_SESSION_KEY);
    let base = kdf::<16>(&sk, b"SMB2AESCMAC\0", b"SmbSign\0").unwrap();
    for bit in 0..sk.len() * 8 {
        assert_ne!(*kdf::<16>(&flip(&sk, bit), b"SMB2AESCMAC\0", b"SmbSign\0").unwrap(), *base);
    }
    for bit in 0..12 * 8 {
        assert_ne!(*kdf::<16>(&sk, &flip(b"SMB2AESCMAC\0", bit), b"SmbSign\0").unwrap(), *base);
    }
    for bit in 0..8 * 8 {
        assert_ne!(*kdf::<16>(&sk, b"SMB2AESCMAC\0", &flip(b"SmbSign\0", bit)).unwrap(), *base);
    }
    // L is part of the input: the 256-bit output does not start with the 128-bit one.
    assert_ne!(kdf::<32>(&sk, b"SMB2AESCMAC\0", b"SmbSign\0").unwrap()[..16], base[..]);
    assert_eq!(kdf::<24>(&sk, b"x", b"y").map(|_| ()), Err(CryptoError::KeyLength));
    assert_eq!(kdf::<16>(&[], b"x", b"y").map(|_| ()), Err(CryptoError::KeyLength));
}

#[test]
fn preauth_any_flipped_bit_changes_the_hash() {
    let msg = hex(BLOG_GCM_NEGOTIATE_REQUEST);
    let mut base = PreauthHash::default();
    base.update(&msg);
    for bit in 0..msg.len() * 8 {
        let mut h = PreauthHash::default();
        h.update(&flip(&msg, bit));
        assert_ne!(h, base, "bit {bit}");
    }
}

#[test]
fn session_key_shorter_than_16_is_zero_padded_and_empty_is_refused() {
    let h = PreauthHash::default();
    let short = derive_session_keys(&[1, 2, 3], &h, None, 1).unwrap();
    let padded = derive_session_keys(&[1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &h, None, 1).unwrap();
    assert_eq!(short.signing.0[..], padded.signing.0[..]);
    derive_session_keys(&[], &h, Some(Cipher::Aes128Gcm), 1).unwrap_err();
    // Only the first 16 bytes count for signing and AES-128 keys...
    let long = derive_session_keys(&[9; 32], &h, Some(Cipher::Aes128Gcm), 1).unwrap();
    let first16 = derive_session_keys(&[9; 16], &h, Some(Cipher::Aes128Gcm), 1).unwrap();
    assert_eq!(long.signing.0[..], first16.signing.0[..]);
    assert_eq!(seal_key_bytes(long.seal.as_ref().unwrap()), seal_key_bytes(first16.seal.as_ref().unwrap()));
    // ...but the full key goes into AES-256 keys.
    let long = derive_session_keys(&[9; 32], &h, Some(Cipher::Aes256Gcm), 1).unwrap();
    let first16 = derive_session_keys(&[9; 16], &h, Some(Cipher::Aes256Gcm), 1).unwrap();
    assert_ne!(seal_key_bytes(long.seal.as_ref().unwrap()), seal_key_bytes(first16.seal.as_ref().unwrap()));
}

#[test]
fn nonces_come_from_the_counter_and_never_repeat() {
    let mut key = seal_key_128([3; 16], 9);
    key.salt = [0xAA, 0xBB, 0xCC, 0xDD];
    let open = open_key_128([3; 16], 9);
    let mut seen = std::collections::HashSet::new();
    for i in 0u64..4 {
        let frame = key.seal(b"payload").unwrap();
        let nonce = &frame[20..36];
        assert_eq!(nonce[..8], i.to_le_bytes());
        assert_eq!(nonce[8..12], [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(nonce[12..], [0; 4]);
        assert!(seen.insert(nonce.to_vec()));
        assert_eq!(open.open(&frame).unwrap(), b"payload");
    }
}

#[test]
fn nonce_counter_ends_the_session_before_it_wraps() {
    let mut key = seal_key_128([3; 16], 9);
    key.counter = u64::MAX - 1;
    key.seal(b"x").unwrap();
    assert_eq!(key.seal(b"x"), Err(CryptoError::NonceExhausted));
    assert_eq!(key.seal(b"x"), Err(CryptoError::NonceExhausted));
}

#[test]
fn random_salt_differs_between_sessions() {
    let h = PreauthHash::default();
    let a = derive_session_keys(&[1; 16], &h, Some(Cipher::Aes128Gcm), 1).unwrap();
    let b = derive_session_keys(&[1; 16], &h, Some(Cipher::Aes128Gcm), 1).unwrap();
    // 2^-32 chance of a false failure.
    assert_ne!(a.seal.unwrap().salt, b.seal.unwrap().salt);
}

// ---------------------------------------------------------------------------------------------
// The rest of the surface: constructors, Debug, Display, randomness
// ---------------------------------------------------------------------------------------------

#[test]
fn raw_key_constructors_check_the_length_and_keep_the_cipher() {
    for (cipher, len) in [(Cipher::Aes128Gcm, 16), (Cipher::Aes256Gcm, 32)] {
        let seal = SealKey::from_bytes(cipher, &vec![5; len], 3).unwrap();
        assert_eq!(seal.cipher(), cipher);
        assert_eq!(seal_key_bytes(&seal), vec![5; len]);
        assert_eq!((seal.session_id, seal.counter), (3, 0));
        let open = OpenKey::from_bytes(cipher, &vec![5; len], 3).unwrap();
        assert_eq!(open_key_bytes(&open), vec![5; len]);
        assert_eq!(open.session_id, 3);
        let mut seal = seal;
        assert_eq!(open.open(&seal.seal(b"round trip").unwrap()).unwrap(), b"round trip");
        for wrong in [len - 1, len + 1, 0, 48] {
            assert_eq!(
                SealKey::from_bytes(cipher, &vec![5; wrong], 3).map(|_| ()),
                Err(CryptoError::KeyLength)
            );
            assert_eq!(
                OpenKey::from_bytes(cipher, &vec![5; wrong], 3).map(|_| ()),
                Err(CryptoError::KeyLength)
            );
        }
    }
    // The two ciphers are not interchangeable.
    let mut seal = SealKey::from_bytes(Cipher::Aes256Gcm, &[5; 32], 3).unwrap();
    let frame = seal.seal(b"x").unwrap();
    assert_eq!(
        OpenKey::from_bytes(Cipher::Aes128Gcm, &[5; 16], 3).unwrap().open(&frame),
        Err(CryptoError::Unauthentic)
    );
}

#[test]
fn debug_output_names_no_key_material() {
    let keys =
        derive_session_keys(&[0xAB; 16], &PreauthHash::default(), Some(Cipher::Aes256Gcm), 0x77).unwrap();
    assert_eq!(format!("{:?}", keys.signing), "SigningKey(..)");
    let seal = format!("{:?}", keys.seal.as_ref().unwrap());
    assert_eq!(seal, "SealKey { cipher: Aes256Gcm, session_id: 119, counter: 0, .. }");
    let open = format!("{:?}", keys.open.as_ref().unwrap());
    assert_eq!(open, "OpenKey { cipher: Aes256Gcm, session_id: 119, .. }");
    let all = format!("{keys:?}");
    assert!(
        all.contains("SigningKey(..)") && all.contains("SealKey {") && all.contains("OpenKey {"),
        "{all}"
    );
    assert!(!all.to_lowercase().contains("ab, ab") && !all.contains("171"), "{all}");
    let mut h = PreauthHash::default();
    assert_eq!(format!("{h:?}"), format!("PreauthHash({})", "00".repeat(64)));
    h.0[0] = 0x1f;
    h.0[63] = 0xa0;
    assert_eq!(format!("{h:?}"), format!("PreauthHash(1f{}a0)", "00".repeat(62)));
}

#[test]
fn server_side_keys_pair_with_the_clients() {
    for cipher in [Cipher::Aes128Gcm, Cipher::Aes256Gcm] {
        let h = blog_a1_hash();
        let gss = [0x31u8; 32];
        let mut client = derive_session_keys(&gss, &h, Some(cipher), 9).unwrap();
        let (mut server_seal, server_open) = super::server_side_keys(&gss, &h, cipher, 9).unwrap();
        let request = client.seal.as_mut().unwrap().seal(b"request").unwrap();
        assert_eq!(server_open.open(&request).unwrap(), b"request");
        let response = server_seal.seal(b"response").unwrap();
        assert_eq!(client.open.as_ref().unwrap().open(&response).unwrap(), b"response");
        // Each direction has its own key.
        assert_eq!(client.open.as_ref().unwrap().open(&request), Err(CryptoError::Unauthentic));
    }
}

#[test]
fn errors_say_what_failed() {
    let all = [
        (CryptoError::BadSignature, "message signature does not verify"),
        (CryptoError::Unauthentic, "encrypted message does not authenticate"),
        (CryptoError::Malformed("short frame"), "malformed transform header: short frame"),
        (CryptoError::WrongSession, "encrypted message for an unknown session"),
        (CryptoError::NonceExhausted, "encryption nonce counter exhausted"),
        (CryptoError::ShortMessage, "message shorter than an SMB2 header"),
        (CryptoError::KeyLength, "key of the wrong length"),
        (CryptoError::NoRandomness, "the OS random generator failed"),
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
    }
}

#[test]
fn random_fills_the_buffer() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    super::random(&mut a).unwrap();
    super::random(&mut b).unwrap();
    // 2^-256 chances of a false failure each.
    assert_ne!(a, [0; 32]);
    assert_ne!(a, b);
    super::random(&mut []).unwrap();
}

#[test]
fn preauth_hash_starts_at_zero() {
    assert_eq!(PreauthHash::default().value(), &[0u8; 64]);
    let mut h = PreauthHash::default();
    h.update(b"");
    // SHA-512 of 64 zero bytes (Python's hashlib).
    assert_eq!(
        h.value()[..],
        hex(&[
            "7be9fda48f4179e611c698a73cff09faf72869431efee6eaad14de0cb44bbf66503f752b7a8eb17083355f3ce6eb7d28",
            "06f236b25af96a24e22b887405c20081"
        ])[..]
    );
}

#[test]
fn sign_refuses_short_messages_and_sets_only_the_signature() {
    let key = SigningKey::from_bytes([1; 16]);
    assert_eq!(key.sign(&mut [0u8; 63]), Err(CryptoError::ShortMessage));
    assert_eq!(key.verify(&[0u8; 47]), Err(CryptoError::ShortMessage));
    let mut msg = vec![0x5Au8; 80];
    key.sign(&mut msg).unwrap();
    assert_eq!(msg[..48], [0x5A; 48]);
    assert_eq!(msg[64..], [0x5A; 16]);
    assert_ne!(msg[48..64], [0x5A; 16]);
    key.verify(&msg).unwrap();
    // A header alone (64 bytes) is a message too.
    let mut head = vec![7u8; 64];
    key.sign(&mut head).unwrap();
    key.verify(&head).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Vectors (generated; see the module comment)
// ---------------------------------------------------------------------------------------------

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: negotiate_request
const PIKE_PA_NEGOTIATE_REQUEST: &[&str] = &[
    "fe534d4240000100000000000000800000000000000000000100000000000000fffe0000000000000000000000000000",
    "0000000000000000000000000000000024000500000000003f000000ecd86f326276024f9f7752b89bb33f3a70000000",
    "020000000202100200030203110300000100260000000000010020000100fa49e6578f1f3a9f4cd3e9cc14a67aa884b3",
    "d05844e0e5a118225c15887f32ff00000200060000000000020002000100",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_pae_1
const PIKE_PA_EXP_PAE_1: &[&str] = &[
    "dd94efc5321bb618a2e208ba8920d2f422992526947a409b5037de1e0fe8c7362b8c47122594cde0ce26aa9dfc8bcdbd",
    "e0621957672623351a7540f1e54a0426",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: negotiate_response
const PIKE_PA_NEGOTIATE_RESPONSE: &[&str] = &[
    "fe534d4240000100000000000000010001000000000000000100000000000000fffe0000000000000000000000000000",
    "00000000000000000000000000000000410001001103020039cbcaf329714942bdce5d60f09ab3fb2f00000000008000",
    "0000800000008000d8dae5adcbaed00109094ab095aed00180004001c00100006082013c06062b0601050502a0820130",
    "3082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f45585453",
    "010000000000000060000000700000007c7cc0fd06d6362d02dde1cf343bfe292900f49750b4aa97934d9c4296b26e51",
    "fd370471b235e15a50dae15bd5489c870000000000000000600000000100000000000000000000005c33530deaf90d4d",
    "b2ec4ae3786ec3084e45474f45585453030000000100000040000000980000007c7cc0fd06d6362d02dde1cf343bfe29",
    "5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f0603550403131854",
    "6f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369",
    "676e696e67205075626c6963204b6579010026000000000001002000010060a3c3b95c3c7ccd51ec536648d9b3ac74c4",
    "83ca5b65385a251117beb30712e50000020004000000000001000200",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_pae_2
const PIKE_PA_EXP_PAE_2: &[&str] = &[
    "324bfa92a4f3a190e466ebea08d9c110dc88bfed758d9846ecc6f541cc1d02ae3c94a79f36011e997e13f841b91b5095",
    "7ad07b19c8e2539c0b23fdae09d2c513",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: session_setup_request
const PIKE_PA_SESSION_SETUP_REQUEST: &[&str] = &[
    "fe534d4240000100000000000100800000000000000000000200000000000000fffe0000000000000000000000000000",
    "0000000000000000000000000000000019000001010000000000000058004a000000000000000000604806062b060105",
    "0502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000",
    "00000000000000000000060380250000000f",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_pae_3
const PIKE_PA_EXP_PAE_3: &[&str] = &[
    "ac0b0f2b9986257700365e416d142a6edc96df03594a19e52a15f6bd0d041cd5d432f8ed42c55e33197a50c9ec00f146",
    "2b50c592211b1471a04b56088fdfd5f9",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: session_setup_response
const PIKE_PA_SESSION_SETUP_RESPONSE: &[&str] = &[
    "fe534d4240000100160000c00100010001000000000000000200000000000000fffe0000000000001900000000100000",
    "00000000000000000000000000000000090000004800b300a181b03081ada0030a0101a10c060a2b0601040182370202",
    "0aa281970481944e544c4d53535000020000000c000c003800000015828ae20d1d8ba31179d008000000000000000050",
    "005000440000000a0092270000000f53005500540033003100310002000c0053005500540033003100310001000c0053",
    "005500540033003100310004000c0053005500540033003100310003000c0053005500540033003100310007000800a1",
    "a1f5adcbaed00100000000",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_pae_4
const PIKE_PA_EXP_PAE_4: &[&str] = &[
    "2729e3440dfddd839e37193f6e8f20c20cefb3469e453a70cd980eec06b8835740a73760085633364c8989895ece81bf",
    "102deeb14d4b7d48afa76901a7a38387",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: session_setup_response2
const PIKE_PA_SESSION_SETUP_RESPONSE2: &[&str] = &[
    "fe534d4240000100000000000100800000000000000000000300000000000000fffe0000000000001900000000100000",
    "000000000000000000000000000000001900000101000000000000005800cf010000000000000000a18201cb308201c7",
    "a0030a0101a28201aa048201a64e544c4d53535000030000001800180090000000ee00ee00a80000000c000c00580000",
    "001a001a0064000000120012007e0000001000100096010000158288e2060380250000000fecac77a5f385a8bf9c38c7",
    "06eeeddcd3530055005400330031003100610064006d0069006e006900730074007200610074006f0072004400520049",
    "0056004500520033003100310000000000000000000000000000000000000000000000000063078eb639fe03e20a231c",
    "3ae3bf23080101000000000000a1a1f5adcbaed001bc4ad05f223cc90f0000000002000c005300550054003300310031",
    "0001000c0053005500540033003100310004000c0053005500540033003100310003000c005300550054003300310031",
    "0007000800a1a1f5adcbaed00106000400020000000800300030000000000000000000000000300000b61fefcaa857ea",
    "57bf1edcebf8974b8e0eba5a6dfd9d07a31d11b548f8c9d0cc0a00100000000000000000000000000000000000090016",
    "0063006900660073002f005300550054003300310031000000000000000000000000003b9bdff38f5ee8f9663f11a0f4",
    "c03a78a31204100100000063775a9a5fd97f0600000000",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_pae_5
const PIKE_PA_EXP_PAE_5: &[&str] = &[
    "0dd13628cc3ed218ef9df9772d436d0887ab9814bfae63a80aa845f36909db7928622dddad522d9751640a459762c5a9",
    "d6bb084cbb3ce6bdadef5d5bce3c6c01",
];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: session_key
const PIKE_PA_SESSION_KEY: &[&str] = &["270e1ba896585eeb7af3472d3b4c75a7"];

/// pike tests/test_smb3_encryption_vector.py test_pre_auth_integrity: exp_signing_key
const PIKE_PA_EXP_SIGNING_KEY: &[&str] = &["73fe7a9a77bef0bde49c650d8ccb5f76"];

/// winlinux smb3-vectors.ts gcm.negotiateRequest
const BLOG_GCM_NEGOTIATE_REQUEST: &[&str] = &[
    "fe534d4240000100000000000000010000000000000000000000000000000000fffe0000000000000000000000000000",
    "000000000000000000000000000000002400050001000000660000004f0d7fa009f5b246b2ef62551d7d7c0970000000",
    "020000000202100200030203110300000100260000000000010020000100d1709d7196e1bd0b6ebf95213d7655343576",
    "3514392649fd6f216ed8bf269cd800000200060000000000020002000100",
];

/// winlinux smb3-vectors.ts gcm.hashAfterNegotiateRequest
const BLOG_GCM_HASH_AFTER_NEGOTIATE_REQUEST: &[&str] = &[
    "550442daf311412870ad9e58e602b0312d61328d6b1ac28f22af46d6ea581f23a9bfabe0cc0411976bf3f9da23d34333",
    "52cb48cf00b8659bc1a3695e1b1a52a8",
];

/// winlinux smb3-vectors.ts gcm.negotiateResponse
const BLOG_GCM_NEGOTIATE_RESPONSE: &[&str] = &[
    "fe534d4240000100000000000000010001000000000000000000000000000000fffe0000000000000000000000000000",
    "00000000000000000000000000000000410001001103020039cbcaf329714942bdce5d60f09ab3fb2700000000008000",
    "0000800000008000d1168e69cdaed00109094ab095aed00180004001c00100006082013c06062b0601050502a0820130",
    "3082012ca01a3018060a2b06010401823702021e060a2b06010401823702020aa282010c048201084e45474f45585453",
    "01000000000000006000000070000000807cc0fd06d6362d02dde1cf343bfe29c16aa4ea4741fb0ef645dc5c5d3c3e6a",
    "8de5d0baef7a06dc070076174356eda00000000000000000600000000100000000000000000000005c33530deaf90d4d",
    "b2ec4ae3786ec3084e45474f4558545303000000010000004000000098000000807cc0fd06d6362d02dde1cf343bfe29",
    "5c33530deaf90d4db2ec4ae3786ec30840000000580000003056a05430523027802530233121301f0603550403131854",
    "6f6b656e205369676e696e67205075626c6963204b65793027802530233121301f06035504031318546f6b656e205369",
    "676e696e67205075626c6963204b65790100260000000000010020000100b51c002c28941192737a08344b05ce90786e",
    "ec146d99cdb60ae44e5a86127d270000020004000000000001000200",
];

/// winlinux smb3-vectors.ts gcm.hashAfterNegotiateResponse
const BLOG_GCM_HASH_AFTER_NEGOTIATE_RESPONSE: &[&str] = &[
    "abe4da6e875f6fb05033af04dcc38c92888b4e13d1eab7aa05cade142064974cb3eab0782600549ba27207aa213b0d19",
    "0b9950fa36d45be32a888bfee8389b74",
];

/// winlinux smb3-vectors.ts gcm.setupRequest1
const BLOG_GCM_SETUP_REQUEST1: &[&str] = &[
    "fe534d4240000100000000000100800000000000000000000100000000000000fffe0000000000000000000000000000",
    "0000000000000000000000000000000019000001010000000000000058004a000000000000000000604806062b060105",
    "0502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000",
    "00000000000000000000060380250000000f",
];

/// winlinux smb3-vectors.ts gcm.hashAfterSetupRequest1
const BLOG_GCM_HASH_AFTER_SETUP_REQUEST1: &[&str] = &[
    "a5e8ab87e2adb8fa5f4545d20f1fd2019d66ccd0f4dfd1f762f1dfc8dcb15b98d0bd1f1450f6a0afc70f80b353c2d959",
    "217681949cf22df35f31257a281c6a80",
];

/// winlinux smb3-vectors.ts gcm.setupResponse1
const BLOG_GCM_SETUP_RESPONSE1: &[&str] = &[
    "fe534d4240000100160000c00100010001000000000000000100000000000000fffe0000000000002500000000100000",
    "00000000000000000000000000000000090000004800b300a181b03081ada0030a0101a10c060a2b0601040182370202",
    "0aa281970481944e544c4d53535000020000000c000c003800000015828ae25fc0cb7f886e93d6000000000000000050",
    "005000440000000a0092270000000f53005500540033003100310002000c0053005500540033003100310001000c0053",
    "005500540033003100310004000c0053005500540033003100310003000c005300550054003300310031000700080024",
    "8d5c6ccdaed00100000000",
];

/// winlinux smb3-vectors.ts gcm.hashAfterSetupResponse1
const BLOG_GCM_HASH_AFTER_SETUP_RESPONSE1: &[&str] = &[
    "9a095455244172898902b0fbdf5fefafd8435bb66a47eb55cb7542732a423f58b12b3ed698bef3878d8a346fd9f5cc88",
    "2da37aaf2a939290e98b935fc72b3944",
];

/// winlinux smb3-vectors.ts gcm.setupRequest2
const BLOG_GCM_SETUP_REQUEST2: &[&str] = &[
    "fe534d4240000100000000000100800000000000000000000200000000000000fffe0000000000002500000000100000",
    "000000000000000000000000000000001900000101000000000000005800cf010000000000000000a18201cb308201c7",
    "a0030a0101a28201aa048201a64e544c4d53535000030000001800180090000000ee00ee00a80000000c000c00580000",
    "001a001a0064000000120012007e0000001000100096010000158288e2060380250000000fa5e34268ef143be5816251",
    "d02c564e9b530055005400330031003100610064006d0069006e006900730074007200610074006f0072004400520049",
    "005600450052003300310031000000000000000000000000000000000000000000000000002c263da5c2d54785e8eda0",
    "552472d3a30101000000000000248d5c6ccdaed001bea7a53e2dc098eb0000000002000c005300550054003300310031",
    "0001000c0053005500540033003100310004000c0053005500540033003100310003000c005300550054003300310031",
    "0007000800248d5c6ccdaed00106000400020000000800300030000000000000000000000000300000b61fefcaa857ea",
    "57bf1edcebf8974b8e0eba5a6dfd9d07a31d11b548f8c9d0cc0a00100000000000000000000000000000000000090016",
    "0063006900660073002f00530055005400330031003100000000000000000000000000133fa6ea154880bb44576c6e24",
    "90bde7a31204100100000067890bd408f5680d00000000",
];

/// winlinux smb3-vectors.ts gcm.hashAfterSetupRequest2
const BLOG_GCM_HASH_AFTER_SETUP_REQUEST2: &[&str] = &[
    "b23f3cbfd69487d9832b79b1594a367cdd950909b774c3a4c412b4fcea9edddba7db256ba2ea30e977f11f9b11324757",
    "8e0e915c6d2a513b8f2fca5707dc8770",
];

/// winlinux smb3-vectors.ts gcm.setupResponse2
const BLOG_GCM_SETUP_RESPONSE2: &[&str] = &[
    "fe534d4240000100000000000100800009000000000000000200000000000000fffe0000000000002500000000100000",
    "6b85a4519a0f3eea35ba946dd3afe6b80900000048001d00a11b3019a0030a0100a3120410010000003932a87523ab66",
    "0100000000",
];

/// winlinux smb3-vectors.ts gcm.sessionKey
const BLOG_GCM_SESSION_KEY: &[&str] = &["419fddf34c1e001909d362ae7fb6af79"];

/// winlinux smb3-vectors.ts gcm.signingKey
const BLOG_GCM_SIGNING_KEY: &[&str] = &["8765949dfeaee105ce9118b45be988f0"];

/// winlinux smb3-vectors.ts gcm.encryptionKey
const BLOG_GCM_ENCRYPTION_KEY: &[&str] = &["a2f5e80e5d59103034f32e52f698e5ec"];

/// winlinux smb3-vectors.ts gcm.decryptionKey
const BLOG_GCM_DECRYPTION_KEY: &[&str] = &["748c50868c90f302962a5c35f5f9a8bf"];

/// winlinux smb3-vectors.ts gcm.writeNonce
const BLOG_GCM_WRITE_NONCE: &[&str] = &["c7d6822d269caf48904c664c"];

/// winlinux smb3-vectors.ts gcm.writePlain
const BLOG_GCM_WRITE_PLAIN: &[&str] = &[
    "fe534d4240000100000000000900010008000000000000000500000000000000fffe0000010000002500000000100000",
    "000000000000000000000000000000003100700017000000000000000000000006000000040000000100000004000000",
    "00000000000000007000000000000000536d623320656e6372797074696f6e2074657374696e67",
];

/// winlinux smb3-vectors.ts gcm.writeTransformed
const BLOG_GCM_WRITE_TRANSFORMED: &[&str] = &[
    "fd534d42bd73d97d2bc9001bcafac0fdff5feebcc7d6822d269caf48904c664c00000000870000000000010025000000",
    "001000006ecdd2a7afc7b47763057a041b8fd4daffe990b70c9e09d36c084e02d14ef247f8bde38acf6256f8b1d3b56f",
    "77fbdeb312fea5e92cbcc1ed8fb2ebbfaa75e49a4a394bb44576545567c24d4c014d47c9fbdfdafd2c4f9b72f8d25645",
    "2620a299f48e29e53d6b61d1c13a19e91af013f00d17e3abc2fc3d36c8c1b6b93973253852dbd442e46ee8",
];

/// winlinux smb3-vectors.ts gcm.responseTransformed
const BLOG_GCM_RESPONSE_TRANSFORMED: &[&str] = &[
    "fd534d42acbe1cb7ed343adf1725ef144d90d4b0e06831dd2e8eb7b40000000000000000500000000000010025000000",
    "0010000026bbbf949983a6c1c796559d0f2c510cb651d1f7b6ac8ded32a2a0b8f2d793a815c6f6b848d69767a215841a",
    "42d400ae6ddb5f0b44173a014973321fdd7950da6179159b82e03c9e18a050ff0ea1c967",
];

/// winlinux smb3-vectors.ts gcm.responsePlain
const BLOG_GCM_RESPONSE_PLAIN: &[&str] = &[
    "fe534d4240000100000000000900010001000000000000000500000000000000fffe0000010000002500000000100000",
    "0000000000000000000000000000000011000000170000000000000000000000",
];

/// winlinux smb3-vectors.ts ccm.hashAfterSetupRequest2
const BLOG_CCM_HASH_AFTER_SETUP_REQUEST2: &[&str] = &[
    "decf98a420718718f22090d3580fcc5e484bd310fa1268210c6e86335a8891e767f5bcd99fa5a7859d665ad07a73ea94",
    "e1bcdb7cfa69a6962a28a244138340b1",
];

/// winlinux smb3-vectors.ts ccm.setupResponse2
const BLOG_CCM_SETUP_RESPONSE2: &[&str] = &[
    "fe534d4240000100000000000100800009000000000000000200000000000000fffe0000000000002100000000100000",
    "3676196aee8ca17e5d50a53642ef2be40900000048001d00a11b3019a0030a0100a3120410010000000f57444342a271",
    "7e00000000",
];

/// winlinux smb3-vectors.ts ccm.sessionKey
const BLOG_CCM_SESSION_KEY: &[&str] = &["07b7f69c1e2581662df6987e88f9e891"];

/// winlinux smb3-vectors.ts ccm.signingKey
const BLOG_CCM_SIGNING_KEY: &[&str] = &["3dcc82c5795ae27f383242761078c59b"];

/// winlinux smb3-vectors.ts ccm.encryptionKey
const BLOG_CCM_ENCRYPTION_KEY: &[&str] = &["dfaaa31aae40a2485d47ac4df09fda1d"];

/// winlinux smb3-vectors.ts ccm.decryptionKey
const BLOG_CCM_DECRYPTION_KEY: &[&str] = &["95c544aef6072680da1ce49a68a97fa6"];

/// winlinux smb3-vectors.ts smb30.sessionKey
const BLOG_SMB30_SESSION_KEY: &[&str] = &["b4546771b515f766a86735532dd6c4f0"];

/// winlinux smb3-vectors.ts smb30.signingKey
const BLOG_SMB30_SIGNING_KEY: &[&str] = &["f773cd23c18fd1e08ee510cada7cf852"];

/// winlinux smb3-vectors.ts smb30.encryptionKey
const BLOG_SMB30_ENCRYPTION_KEY: &[&str] = &["261b72350558f2e9dcf613070383edbf"];

/// winlinux smb3-vectors.ts smb30.decryptionKey
const BLOG_SMB30_DECRYPTION_KEY: &[&str] = &["8fe2b57ec34d2db5b1a9727f526bbdb5"];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 1 c2s len 216 proto fe534d42 cmd 0
const WS128_FRAME1: &[&str] = &[
    "fe534d424000000000000000000002000000000000000000000000000000000014010000000000000000000000000000",
    "0000000000000000000000000000000024000100010000007700000072c1bb25b9284fbb9773a3f3e62a299968000000",
    "04000000110300000100260000000000010020000100dddc41616260031c5db1644cb443984ffe4a4e1cf5fea8210205",
    "4601233673c300000200060000000000020002000100000003000e000000000003000000000000000200030001000000",
    "000110000000000093ad25509cb411e7b42383de968bcd7c",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 2 s2c len 308 proto fe534d42 cmd 0
const WS128_FRAME2: &[&str] = &[
    "fe534d424000000000000000000001000100000000000000000000000000000014010000000000000000000000000000",
    "000000000000000000000000000000004100010011030200de1f86b985f81c44a719669ef403e3462700000000008000",
    "0000800000008000d52e586ad422d501a3519770d105d50180007800f8000000607606062b0601050502a06c306aa03c",
    "303a060a2b06010401823702021e06092a864882f71201020206092a864886f712010202060a2a864886f71201020203",
    "060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173",
    "655f69676e6f72650100260000000000010020000100e1d08be31f375dfea0bd50267a27e7b790b31be1a97f13addf0f",
    "9ee06b30a1200000020004000000000001000200",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 3 c2s len 120 proto fe534d42 cmd 1
const WS128_FRAME3: &[&str] = &[
    "fe534d424000000000000000010082000000000000000000010000000000000014010000000000000000000000000000",
    "000000000000000000000000000000001900000100000000000000005800200000000000000000004e544c4d53535000",
    "01000000250208e000000000000000000000000000000000",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 4 s2c len 258 proto fe534d42 cmd 1
const WS128_FRAME4: &[&str] = &[
    "fe534d4240000000160000c0010001000100000000000000010000000000000014010000000000003900000000400000",
    "00000000000000000000000000000000090000004800ba004e544c4d53535000020000000600060038000000250289e2",
    "70bb92bbb2b0171800000000000000007c007c003e0000000a0039380000000f46004f004f000200060046004f004f00",
    "0100100044004600530052004f004f00540031000400100066006f006f002e0074006500730074000300220064006600",
    "730072006f006f00740031002e0066006f006f002e0074006500730074000500100066006f006f002e00740065007300",
    "740007000800a4515f6ad422d50100000000",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 5 c2s len 364 proto fe534d42 cmd 1
const WS128_FRAME5: &[&str] = &[
    "fe534d424000000000000000010082000000000000000000020000000000000014010000000000003900000000400000",
    "000000000000000000000000000000001900000100000000000000005800140100000000000000004e544c4d53535000",
    "030000000000000040000000a800a8004000000000000000e80000001a001a00e8000000000000000201000010001000",
    "04010000250288e06320f55b68af693613c1d74a6ebd438a0101000000000000a4515f6ad422d501d01a406be4e034f1",
    "000000000200060046004f004f000100100044004600530052004f004f00540031000400100066006f006f002e007400",
    "6500730074000300220064006600730072006f006f00740031002e0066006f006f002e00740065007300740005001000",
    "66006f006f002e00740065007300740007000800a4515f6ad422d50100000000610064006d0069006e00690073007400",
    "7200610074006f00720000005fc141ebb32e18a6a13a7e28eb42b17a",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 6 s2c len 72 proto fe534d42 cmd 1
const WS128_FRAME6: &[&str] = &[
    "fe534d424000000000000000010082000900000000000000020000000000000014010000000000003900000000400000",
    "a9ab185bd1a0b06d9cbe3570983d4c0d0900000048000000",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 7 c2s len 174 proto fd534d42 cmd None
const WS128_FRAME7: &[&str] = &[
    "fd534d425fffec2923c8e8f7864e6ee1b8ba70d7bcb64ee680149a5d98311914000000007a0000000000010039000000",
    "004000004794151bb1748542d4c79c1923d9986bdef357d821c1fcee19bf5e637dcd46a69208d40c110cd34dc1dfad8e",
    "36d2035ef83648f1d2f7829f7bab34aa9b63dd7811a31bf7ac3a0e62718f51d6549791cf79b6b4cb889ee1338ca62a21",
    "6092afd93c3279b78ccbb925c7347083b5faae959d2cf777d5e3786eee92",
];

/// Wireshark test/captures/smb311-aes-128-gcm.pcap.gz frame 8 s2c len 132 proto fd534d42 cmd None
const WS128_FRAME8: &[&str] = &[
    "fd534d4285e5483e828897c300416eb199043a1081eb4dc01d20a08e0000000000000000500000000000010039000000",
    "0040000089d1444bab08bf54328851e6ac644da7bdc5c33fd909f5576c2f76d4285ab7711e8e13b6cb983e7f1fac0a79",
    "c36b8c362adf11aebeb4130975fcceebac53df479e36763d4e505451877c1505fbaea5be",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 1 c2s len 224 proto fe534d42 cmd 0
const WS256_FRAME1: &[&str] = &[
    "fe534d42400000000000000000001f000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000024000500030000007f00000054119e6703be1e47b529647c33a9b8f470000000",
    "040000000202100200030203110300000100260000000000010020000100a012bc634af4af10cb99bbe472bf2f8f85c2",
    "4bd8f0b0962fb042e28747d56f0600000200040000000000010004000000000008000800000000000300020001000000",
    "05001800000000003100370032002e00330031002e0039002e00310036003300",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 2 s2c len 300 proto fe534d42 cmd 0
const WS256_FRAME2: &[&str] = &[
    "fe534d424000000000000000000001000100000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000041000300110303007562313430342d3136330000000000000d00000000008000",
    "00008000000080007cdb41c1dc16d801000000000000000080006000e0000000605e06062b0601050502a0543052a024",
    "302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f",
    "646566696e65645f696e5f5246433431373840706c656173655f69676e6f72650100260000000000010020000100a487",
    "67bf377ecead288f09dadb58384e7cd0097a3725c38160b110c339ba7422000002000400000000000100040000000000",
    "080004000000000001000200",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 3 c2s len 162 proto fe534d42 cmd 1
const WS256_FRAME3: &[&str] = &[
    "fe534d424000010000000000010000201000000000000000010000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000019000003010000000000000058004a000000000000000000604806062b060105",
    "0502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000035820862000000002800",
    "00000000000028000000060100000000000f",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 4 s2c len 325 proto fe534d42 cmd 1
const WS256_FRAME4: &[&str] = &[
    "fe534d4240000100160000c00100010011000000000000000100000000000000000000000000000056dc03ab00000000",
    "00000000000000000000000000000000090000004800fd00a181fa3081f7a0030a0101a10c060a2b0601040182370202",
    "0aa281e10481de4e544c4d5353500002000000120012003800000035828962bc76f03df077120d000000000000000094",
    "0094004a000000060100000000000f57003400450044004f004d002d004c0034000200120057003400450044004f004d",
    "002d004c003400010014005500420031003400300034002d0031003600330004001c0077003400650064006f006d002d",
    "006c0034002e006200610073006500030032007500620031003400300034002d003100360033002e0077003400650064",
    "006f006d002d006c0034002e00620061007300650007000800fc2c43c1dc16d80100000000",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 5 c2s len 622 proto fe534d42 cmd 1
const WS256_FRAME5: &[&str] = &[
    "fe534d4240000100000000000100002010000000000000000200000000000000000000000000000056dc03ab00000000",
    "00000000000000000000000000000000190000030100000000000000580016020000000000000000a18202123082020e",
    "a28201f6048201f24e544c4d53535000030000001800180058000000360136017000000012001200a60100001a001a00",
    "b801000010001000d201000010001000e201000035820862060100000000000fb6b5a6ccdbc8a78f59dfb319ae0853b7",
    "0000000000000000000000000000000000000000000000006fc2eb0ba4f518294e58f2098a0d0f180101000000000000",
    "fc2c43c1dc16d8012d07f90122ce2f7b000000000200120057003400450044004f004d002d004c003400010014005500",
    "420031003400300034002d0031003600330004001c0077003400650064006f006d002d006c0034002e00620061007300",
    "6500030032007500620031003400300034002d003100360033002e0077003400650064006f006d002d006c0034002e00",
    "620061007300650007000800fc2c43c1dc16d80106000400020000000800300030000000000000000000000000000000",
    "137cb24ca2aaad5104b4b59e7964ecedd2583790419a647c3a98b34bdddecd6b0a001000000000000000000000000000",
    "000000000900220063006900660073002f003100370032002e00330031002e0039002e00310036003300000000005700",
    "4f0052004b00470052004f0055005000610064006d0069006e006900730074007200610074006f007200530045005200",
    "4e004f0058003100390087d0e481465d717d0d48c057d7e2ff1da312041001000000a84e78f9eb8852a400000000",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 6 s2c len 101 proto fe534d42 cmd 1
const WS256_FRAME6: &[&str] = &[
    "fe534d4240000100000000000100002019000000000000000200000000000000000000000000000056dc03ab00000000",
    "06a6cbeb0a9b20434db9aee0620231740900000048001d00a11b3019a0030a0100a3120410010000005aa3be9e8199f8",
    "a800000000",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 7 c2s len 162 proto fd534d42 cmd None
const WS256_FRAME7: &[&str] = &[
    "fd534d4206afa4803a8342df81f91427ceb68f9c01000000000000000a6bb5c2000000006e0000000000010056dc03ab",
    "00000000a5a49fd70fc8fbfde44575a9c8738169a922075839e6e1fc6e4c9acb7fc03f4f300721df38ec3c08e7f92574",
    "36830f98d58a69e29ab929ab3f963ad856e853cfb52bd9d18dee2d6ce0206c03a623ddbf7c658d808f4dfcadc15705a1",
    "1a78716f9f04438431df1caaa4b140c66b30",
];

/// Wireshark test/captures/smb311-aes-256-gcm.pcap.gz frame 8 s2c len 132 proto fd534d42 cmd None
const WS256_FRAME8: &[&str] = &[
    "fd534d42d1a382aa2268d43a30ba59900a8602960100000000000000f37d0b4300000000500000000000010056dc03ab",
    "00000000547a0cfa79eddcd2206741ab1321b2dc8493867735708b03c08da7cdb2d01731373531e6ac10eaec5cc69ad6",
    "3996d91983298535a04b17ab53b8d999d51861441d5dd6cae0e9519dacde7d9d9167cdaa",
];
