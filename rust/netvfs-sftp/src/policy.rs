// SPDX-License-Identifier: LGPL-2.1-or-later
//! The hardened algorithm lists (S-1, S-2, S-5) and the name of the list a
//! failed negotiation found nothing in.

use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{AlgorithmKind, Preferred, SshId, cipher, client, compression, kex, mac};
use std::borrow::Cow;

/// Key exchange: hybrid ML-KEM, X25519 (both names), then the client
/// markers for ext-info (RFC 8308) and OpenSSH's strict kex; russh never
/// picks a marker.
pub const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// AEAD ciphers only.
pub const CIPHERS: &[cipher::Name] = &[cipher::CHACHA20_POLY1305, cipher::AES_256_GCM, cipher::AES_128_GCM];

/// Unused with AEAD ciphers; encrypt-then-MAC SHA-2 so that nothing weaker
/// can be picked.
pub const MACS: &[mac::Name] = &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM];

/// No compression.
pub const COMPRESSION: &[compression::Name] = &[compression::NONE];

/// Host-key algorithms, preferred first: no `ssh-rsa` signatures (SHA-1),
/// no DSA, no certificates.
pub const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
];

/// The host-key algorithm of a pinned key type (an identity's algorithm,
/// `ssh-keygen`'s key type name); `None` for a type this app does not
/// accept, which then narrows nothing (S-5).
#[must_use]
pub fn pinned_algorithm(key_type: &str) -> Option<Algorithm> {
    match key_type {
        "ssh-ed25519" => Some(Algorithm::Ed25519),
        "ecdsa-sha2-nistp256" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }),
        "ecdsa-sha2-nistp384" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }),
        "ecdsa-sha2-nistp521" => Some(Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }),
        "ssh-rsa" => Some(Algorithm::Rsa { hash: None }),
        _ => None,
    }
}

/// The lists, the host keys narrowed to the pinned type (S-5). An RSA pin
/// keeps both `rsa-sha2-*`: the key is the same, the hash differs.
#[must_use]
pub fn preferred(pin: Option<&Algorithm>) -> Preferred {
    let key: Cow<'static, [Algorithm]> = match pin {
        None => Cow::Borrowed(HOST_KEYS),
        Some(Algorithm::Rsa { .. }) => {
            Cow::Owned(HOST_KEYS.iter().filter(|a| matches!(a, Algorithm::Rsa { .. })).cloned().collect())
        }
        Some(other) => Cow::Owned(HOST_KEYS.iter().filter(|a| *a == other).cloned().collect()),
    };
    Preferred {
        kex: Cow::Borrowed(KEX),
        key,
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(CIPHERS),
        mac: Cow::Borrowed(MACS),
        compression: Cow::Borrowed(COMPRESSION),
    }
}

/// The client configuration: the lists, no automatic keepalive or
/// inactivity timeout (`keepAlive()` is the caller's, XS-12).
#[must_use]
pub fn config(pin: Option<&Algorithm>) -> client::Config {
    client::Config {
        client_id: SshId::Standard(Cow::Borrowed(concat!("SSH-2.0-netvfs_", env!("CARGO_PKG_VERSION")))),
        preferred: preferred(pin),
        inactivity_timeout: None,
        keepalive_interval: None,
        nodelay: true,
        ..client::Config::default()
    }
}

/// For a negotiation that found nothing in common: the list (as the
/// message names it) and what the server offered in it, without the
/// ext-info and strict-kex markers.
#[must_use]
pub fn no_common_algorithm(e: &russh::Error) -> Option<(&'static str, Vec<String>)> {
    let russh::Error::NoCommonAlgo { kind, theirs, .. } = e else {
        return None;
    };
    let list = match kind {
        AlgorithmKind::Kex => "key exchange",
        AlgorithmKind::Key => "host key",
        AlgorithmKind::Cipher => "cipher",
        AlgorithmKind::Mac => "MAC",
        AlgorithmKind::Compression => "compression",
    };
    let offered = theirs.iter().filter(|n| !is_marker(n)).cloned().collect();
    Some((list, offered))
}

/// Whether the negotiation failed on the host-key list (a pin the server
/// no longer offers, S-5).
#[must_use]
pub fn is_host_key_mismatch(e: &russh::Error) -> bool {
    matches!(e, russh::Error::NoCommonAlgo { kind: AlgorithmKind::Key, .. })
}

/// The pseudo-algorithms of kex lists (RFC 8308 ext-info, strict kex).
fn is_marker(name: &str) -> bool {
    name.starts_with("ext-info-") || name.starts_with("kex-strict-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<T: AsRef<str>>(list: &[T]) -> Vec<&str> {
        list.iter().map(AsRef::as_ref).collect()
    }

    #[test]
    fn the_lists() {
        assert_eq!(
            names(KEX),
            [
                "mlkem768x25519-sha256",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ext-info-c",
                "kex-strict-c-v00@openssh.com"
            ]
        );
        assert_eq!(
            names(CIPHERS),
            ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]
        );
        assert_eq!(names(MACS), ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]);
        assert_eq!(names(COMPRESSION), ["none"]);
        let keys: Vec<String> = HOST_KEYS.iter().map(ToString::to_string).collect();
        assert_eq!(
            keys,
            [
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "rsa-sha2-512",
                "rsa-sha2-256"
            ]
        );
    }

    #[test]
    fn a_pin_narrows_the_host_keys() {
        assert_eq!(preferred(None).key.as_ref(), HOST_KEYS);
        for (key_type, expected) in [
            ("ssh-ed25519", vec![Algorithm::Ed25519]),
            ("ecdsa-sha2-nistp256", vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }]),
            ("ecdsa-sha2-nistp384", vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }]),
            ("ecdsa-sha2-nistp521", vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }]),
            (
                "ssh-rsa",
                vec![
                    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
                ],
            ),
        ] {
            let pin = pinned_algorithm(key_type).unwrap();
            assert_eq!(preferred(Some(&pin)).key.as_ref(), expected.as_slice(), "{key_type}");
        }
        for other in ["ssh-dss", "rsa-sha2-512", "sk-ssh-ed25519@openssh.com", "", "SSH-ED25519"] {
            assert_eq!(pinned_algorithm(other), None, "{other}");
        }
        // Everything but the host keys stays.
        let p = preferred(Some(&Algorithm::Ed25519));
        assert_eq!((p.kex.as_ref(), p.cipher.as_ref(), p.mac.as_ref()), (KEX, CIPHERS, MACS));
        assert_eq!(p.compression.as_ref(), COMPRESSION);
        assert!(p.host_key_certificates.is_empty());
    }

    #[test]
    fn the_config() {
        let c = config(None);
        assert_eq!(c.preferred.key.as_ref(), HOST_KEYS);
        assert_eq!((c.inactivity_timeout, c.keepalive_interval, c.nodelay), (None, None, true));
        let SshId::Standard(id) = &c.client_id else { panic!("{:?}", c.client_id) };
        assert!(id.starts_with("SSH-2.0-netvfs_"), "{id}");
        assert_eq!(config(Some(&Algorithm::Ed25519)).preferred.key.as_ref(), [Algorithm::Ed25519]);
    }

    #[test]
    fn failed_negotiations_name_the_list() {
        let e = |kind| russh::Error::NoCommonAlgo {
            kind,
            ours: vec!["ours".to_owned()],
            theirs: vec![
                "a".to_owned(),
                "ext-info-s".to_owned(),
                "kex-strict-s-v00@openssh.com".to_owned(),
                "b".to_owned(),
            ],
        };
        for (kind, list) in [
            (AlgorithmKind::Kex, "key exchange"),
            (AlgorithmKind::Key, "host key"),
            (AlgorithmKind::Cipher, "cipher"),
            (AlgorithmKind::Mac, "MAC"),
            (AlgorithmKind::Compression, "compression"),
        ] {
            let failed = e(kind);
            assert_eq!(no_common_algorithm(&failed), Some((list, vec!["a".to_owned(), "b".to_owned()])));
            assert_eq!(is_host_key_mismatch(&failed), list == "host key");
        }
        assert_eq!(no_common_algorithm(&russh::Error::Disconnect), None);
        assert!(!is_host_key_mismatch(&russh::Error::Disconnect));
    }
}
