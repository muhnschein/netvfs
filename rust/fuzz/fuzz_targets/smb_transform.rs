// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-smb integrity glue: frame never opens without its key; sealed or signed message round-trips, not with a bit flipped.
//! Byte 0 picks the cipher, next two the bit, rest is the message.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_smb::crypto::{Cipher, OpenKey, SealKey, SigningKey};

const SESSION: u64 = 0x0000_4000_0000_0011;

fuzz_target!(|data: &[u8]| {
    let [pick, lo, hi, msg @ ..] = data else { return };
    let at = usize::from(u16::from_le_bytes([*lo, *hi]));
    let (cipher, key) =
        if pick & 1 == 0 { (Cipher::Aes128Gcm, &[0x5a; 32][..16]) } else { (Cipher::Aes256Gcm, &[0x5a; 32][..]) };
    let open = OpenKey::from_bytes(cipher, key, SESSION).unwrap();
    assert!(open.open(data).is_err());

    let mut seal = SealKey::from_bytes(cipher, key, SESSION).unwrap();
    let Ok(frame) = seal.seal(msg) else { return };
    assert_eq!(open.open(&frame).unwrap(), msg);
    let mut flipped = frame.clone();
    let bit = at % ((flipped.len() - 4) * 8);
    flipped[4 + bit / 8] ^= 1 << (bit % 8);
    assert!(open.open(&flipped).is_err());
    let other = OpenKey::from_bytes(cipher, &[0xa5; 32][..key.len()], SESSION).unwrap();
    assert!(other.open(&frame).is_err());

    if msg.len() >= 64 {
        let signing = SigningKey::from_bytes([0x3c; 16]);
        let mut signed = msg.to_vec();
        signing.sign(&mut signed).unwrap();
        signing.verify(&signed).unwrap();
        let bit = at % (signed.len() * 8);
        signed[bit / 8] ^= 1 << (bit % 8);
        assert!(signing.verify(&signed).is_err());
    }
});
