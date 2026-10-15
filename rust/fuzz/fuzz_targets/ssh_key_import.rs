// SPDX-License-Identifier: LGPL-2.1-or-later
//! Key files a user picks (SPEC-sftp 5.1, S-15): importing never panics;
//! an imported key is Ed25519 or ECDSA, its public line and fingerprint
//! are well-formed, and describing the stored key gives the same material;
//! describing never decrypts. Key secrets encode and decode losslessly;
//! an empty one decodes to nothing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use netvfs_sftp::keys;

fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (file, passphrase) = input;
    if let Ok(key) = keys::import(&file, &passphrase) {
        assert!(
            ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"]
                .contains(&key.algorithm.as_str()),
            "{}",
            key.algorithm
        );
        assert!(key.public_line.starts_with(&format!("{} AAAA", key.algorithm)));
        assert!(key.public_line.ends_with(&format!(" {}", keys::PUBLIC_KEY_COMMENT)));
        assert!(key.fingerprint.starts_with("SHA256:") && key.fingerprint.len() == 50);
        assert_eq!(keys::describe(&key.private_key).expect("a stored key describes"), key);
    }
    if let Ok(key) = keys::describe(&file) {
        assert_eq!(keys::import(&file, b"").expect("what describes imports"), key);
    }
    let secret = keys::encode_key_secret(&file);
    assert!(keys::is_key_secret(&secret));
    let expected = Some(&file[..]).filter(|key| !key.is_empty());
    assert_eq!(keys::decode_key_secret(&secret).as_deref().map(Vec::as_slice), expected);
});
