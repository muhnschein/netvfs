// SPDX-License-Identifier: LGPL-2.1-or-later
//! The key files in `testdata/keys` were made with ssh-keygen (OpenSSH
//! 9.6p1) and openssl 3.0.13; `golden.txt` holds what the libssh-based
//! C++ key tools made of each of them before they were removed: the
//! Ed25519 and ECDSA keys must come out the same here, byte for byte.

use super::*;

const PASSPHRASE: &[u8] = b"correct-horse";
const WRONG: &[u8] = b"wrong-pass";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/testdata/keys/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn refusal(r: Result<KeyMaterial, Status>) -> (ErrorName, String) {
    let e = r.unwrap_err();
    (e.name, e.message)
}

fn unsupported(message: &str) -> (ErrorName, String) {
    (ErrorName::Unsupported, message.to_owned())
}

fn auth(message: &str) -> (ErrorName, String) {
    (ErrorName::AuthFailed, message.to_owned())
}

const RSA: &str = "RSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
const DSA: &str = "DSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key";
const LEGACY: &str = "Keys encrypted in the legacy PEM format are not supported; generate a new key";
const NOT_A_KEY: &str = "The file is not a private key in OpenSSH or PEM format";
const UNUSABLE: &str = "The file is not a key this app can use (Ed25519 or ECDSA in OpenSSH or PEM format)";
const PROTECTED: &str = "The key is protected by a passphrase";
const NOT_CORRECT: &str = "The passphrase is not correct";

/// One line of `golden.txt`: `file | passphrase | ok | algorithm | public
/// line | fingerprint` or `file | passphrase | error | name | message`.
struct Golden {
    file: String,
    passphrase: Vec<u8>,
    outcome: Result<(String, String, String), (String, String)>,
}

fn golden() -> Vec<Golden> {
    let text = String::from_utf8(fixture("golden.txt")).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split(" | ").collect();
            let passphrase = match f[1] {
                "-" => Vec::new(),
                "right" => PASSPHRASE.to_vec(),
                "wrong" => WRONG.to_vec(),
                other => panic!("{other}"),
            };
            let outcome = match f[2] {
                "ok" => Ok((f[3].to_owned(), f[4].to_owned(), f[5].to_owned())),
                "error" => Err((f[3].to_owned(), f[4].to_owned())),
                other => panic!("{other}"),
            };
            Golden { file: f[0].to_owned(), passphrase, outcome }
        })
        .collect()
}

#[test]
fn ed25519_and_ecdsa_keys_come_out_as_the_libssh_tools_made_them() {
    let (mut accepted, mut refused, mut changed) = (0, 0, 0);
    for g in golden() {
        let got = import(&fixture(&g.file), &g.passphrase);
        let what = format!("{} with {:?}", g.file, String::from_utf8_lossy(&g.passphrase));
        // What changed on purpose: RSA keys and legacy encrypted PEM were
        // accepted by libssh and are refused now, whatever the passphrase.
        let now_refused = if g.file.starts_with("rsa-") {
            Some(RSA)
        } else if g.file.ends_with("-legacyenc") {
            Some(LEGACY)
        } else {
            None
        };
        match (now_refused, g.outcome) {
            (Some(message), _) => {
                assert_eq!(refusal(got), unsupported(message), "{what}");
                changed += 1;
            }
            (None, Ok((algorithm, line, fingerprint))) => {
                let key = got.unwrap_or_else(|e| panic!("{what}: {e:?}"));
                assert_eq!(
                    (key.algorithm, key.public_line, key.fingerprint),
                    (algorithm, line, fingerprint),
                    "{what}"
                );
                accepted += 1;
            }
            (None, Err((name, message))) => {
                // The DSA message no longer suggests RSA.
                let message = if g.file.starts_with("dsa-") { DSA.to_owned() } else { message };
                let (got_name, got_message) = refusal(got);
                assert_eq!((format!("{got_name:?}"), got_message), (name, message), "{what}");
                refused += 1;
            }
        }
    }
    assert_eq!((accepted, refused, changed), (13, 15, 12));
}

#[test]
fn fingerprints_are_the_ones_ssh_keygen_prints() {
    // `ssh-keygen -lf <file>.pub`, OpenSSH 9.6p1.
    for (file, passphrase, expected) in [
        ("ed25519-openssh", &b""[..], "SHA256:ZGPW31uwJF+/lR0hhEstPwJCRwMYsx0C3T2YPcRL/3c"),
        ("ed25519-openssh-enc", PASSPHRASE, "SHA256:V3dDf1W0ahmN12EbuUrVqKGy5H6JjR9COfxe/qTnMXA"),
        ("ecdsa256-openssh-enc", PASSPHRASE, "SHA256:SNWJ21BVWCzQsk85ZyyesWyjOtDfbrKuDgyWGZL230o"),
        ("ecdsa384-openssh", b"", "SHA256:a/xciQX6h6MjX1LfE2A3wscREIa1TDh2SEIot7+BZ0k"),
        ("ecdsa521-openssh", b"", "SHA256:bBjqHz+u3v9oFDtTvN/rqfQvkJGXZgdKwAib0NUmqZk"),
        ("ecdsa256-pkcs8", b"", "SHA256:pWre/J4xCEqz4Sug+7R22xl6gL093vNj/PmBYnWiE+Q"),
        ("ecdsa256-sec1", b"", "SHA256:zTzly0CmpuUxbn1GTWJLooirxac7YtHpHdR4Su2PLk0"),
    ] {
        assert_eq!(import(&fixture(file), passphrase).unwrap().fingerprint, expected, "{file}");
    }
}

#[test]
fn public_lines_carry_the_blob_of_the_pub_file() {
    for file in ["ed25519-openssh", "ecdsa384-openssh", "ecdsa521-openssh", "ecdsa256-pkcs8", "ecdsa256-sec1"]
    {
        let key = import(&fixture(file), b"").unwrap();
        let pub_file = String::from_utf8(fixture(&format!("{file}.pub"))).unwrap();
        let fields: Vec<&str> = pub_file.split_whitespace().collect();
        assert_eq!(key.public_line, format!("{} {} sailfish-backup", fields[0], fields[1]), "{file}");
        assert_eq!(key.algorithm, fields[0]);
    }
}

#[test]
fn encrypted_keys_need_the_right_passphrase() {
    for file in [
        "ed25519-openssh-enc",
        "ecdsa256-openssh-enc",
        "ed25519-pkcs8-enc",
        "ecdsa256-pkcs8-enc",
        "ecdsa256-pkcs8-scrypt",
    ] {
        let key = import(&fixture(file), PASSPHRASE).unwrap();
        assert_eq!(refusal(import(&fixture(file), b"")), auth(PROTECTED), "{file}");
        assert_eq!(refusal(import(&fixture(file), WRONG)), auth(NOT_CORRECT), "{file}");
        assert_eq!(refusal(describe(&fixture(file))), auth(PROTECTED), "{file}");
        // Stored unencrypted, in OpenSSH format, without the comment.
        let text = std::str::from_utf8(&key.private_key).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"), "{file}");
        let stored = PrivateKey::from_openssh(text).unwrap();
        assert!(!stored.is_encrypted());
        assert!(stored.comment().is_empty());
        assert_eq!(describe(&key.private_key).unwrap(), key);
    }
    // A passphrase that is not UTF-8 cannot be a PKCS#8 one.
    assert_eq!(refusal(import(&fixture("ed25519-pkcs8-enc"), b"\xff")), auth(NOT_CORRECT));
    // A plain key takes no passphrase, and ignores one.
    import(&fixture("ed25519-openssh"), WRONG).unwrap();
    import(&fixture("ecdsa256-pkcs8"), WRONG).unwrap();
}

#[test]
fn refused_keys_name_the_fix() {
    for (file, passphrase, expected) in [
        ("rsa-openssh", &b""[..], unsupported(RSA)),
        // Refused before the passphrase is asked for.
        ("rsa-openssh-enc", b"", unsupported(RSA)),
        ("rsa-openssh-enc", PASSPHRASE, unsupported(RSA)),
        ("rsa-pem-pkcs1", b"", unsupported(RSA)),
        ("rsa-pkcs8", b"", unsupported(RSA)),
        ("rsa-pem-legacyenc", PASSPHRASE, unsupported(RSA)),
        ("dsa-openssh", b"", unsupported(DSA)),
        ("dsa-pem-openssl", b"", unsupported(DSA)),
        ("ecdsa256-pem-legacyenc", b"", unsupported(LEGACY)),
        ("ecdsa256-pem-legacyenc", PASSPHRASE, unsupported(LEGACY)),
        ("putty.ppk", b"", unsupported(NOT_A_KEY)),
        (
            "ed25519-cert-cert.pub",
            b"",
            unsupported("SSH certificates are not supported; choose a private key file"),
        ),
        ("ed25519-openssh.pub", b"", unsupported("This is a public key; choose the private key file")),
        ("rsa-openssh.pub", b"", unsupported("This is a public key; choose the private key file")),
    ] {
        assert_eq!(refusal(import(&fixture(file), passphrase)), expected, "{file}");
    }
}

#[test]
fn files_that_are_no_keys() {
    let cases: [(&[u8], (ErrorName, String)); 9] = [
        (b"", unsupported(NOT_A_KEY)),
        (b"not a key", unsupported(NOT_A_KEY)),
        (b"\xff\xfe", unsupported(NOT_A_KEY)),
        (b"ssh-ed25519 notbase64 comment", unsupported(NOT_A_KEY)),
        (b"ssh-ed25519", unsupported(NOT_A_KEY)),
        (b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", unsupported(NOT_A_KEY)),
        (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            unsupported(UNUSABLE),
        ),
        (b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", unsupported(UNUSABLE)),
        (b"-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n", unsupported(UNUSABLE)),
    ];
    for (text, expected) in cases {
        assert_eq!(refusal(import(text, b"")), expected, "{}", String::from_utf8_lossy(text));
    }
    // Leading blank lines and indentation do not hide a key.
    let mut padded = b"\n\n  ".to_vec();
    padded.extend(fixture("ed25519-openssh"));
    import(&padded, b"").unwrap();
    // A file too large to be a key is not read.
    let mut large = fixture("ed25519-openssh");
    large.resize(MAX_KEY_FILE + 1, b'\n');
    assert_eq!(refusal(import(&large, b"")), unsupported(NOT_A_KEY));
    large.truncate(MAX_KEY_FILE);
    import(&large, b"").unwrap();
}

#[test]
fn the_algorithms() {
    check_algorithm(&Algorithm::Ed25519).unwrap();
    for curve in [EcdsaCurve::NistP256, EcdsaCurve::NistP384, EcdsaCurve::NistP521] {
        check_algorithm(&Algorithm::Ecdsa { curve }).unwrap();
    }
    for hash in [None, Some(HashAlg::Sha256), Some(HashAlg::Sha512)] {
        assert_eq!(check_algorithm(&Algorithm::Rsa { hash }).unwrap_err().message, RSA);
    }
    assert_eq!(check_algorithm(&Algorithm::Dsa).unwrap_err().message, DSA);
    for sk in [Algorithm::SkEd25519, Algorithm::SkEcdsaSha2NistP256] {
        assert_eq!(check_algorithm(&sk).unwrap_err().message, "Security-key (FIDO) keys are not supported");
    }
    let other = Algorithm::new("x-unknown@example.org").unwrap();
    assert_eq!(
        check_algorithm(&other).unwrap_err().message,
        "Key type x-unknown@example.org is not supported; generate a new key, or use an Ed25519 or ECDSA key"
    );
}

#[test]
fn generated_keys() {
    let first = generate().unwrap();
    let second = generate().unwrap();
    assert_ne!(first.public_line, second.public_line);
    assert_ne!(first.private_key, second.private_key);
    assert_eq!(first.algorithm, "ssh-ed25519");
    let fields: Vec<&str> = first.public_line.split(' ').collect();
    assert_eq!((fields.len(), fields[0], fields[2]), (3, "ssh-ed25519", "sailfish-backup"));
    assert!(fields[1].starts_with("AAAAC3NzaC1lZDI1NTE5"), "{}", fields[1]);
    assert!(first.fingerprint.starts_with("SHA256:"));
    assert_eq!(first.fingerprint.len(), 50);
    assert_eq!(describe(&first.private_key).unwrap(), first);
    let stored = PrivateKey::from_openssh(&*first.private_key).unwrap();
    assert!(!stored.is_encrypted());
    assert_eq!(fingerprint(stored.public_key()), first.fingerprint);
}

#[test]
fn debug_output_leaves_out_the_private_key() {
    let key = generate().unwrap();
    let shown = format!("{key:?}");
    assert!(shown.contains("ssh-ed25519") && shown.contains(&key.fingerprint), "{shown}");
    assert!(!shown.contains("PRIVATE"), "{shown}");
}

#[test]
fn key_secrets() {
    let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n";
    let secret = encode_key_secret(key);
    assert_eq!(secret.as_slice(), b"netvfs-key-v1:LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYWJjCg==");
    assert!(is_key_secret(&secret));
    assert_eq!(decode_key_secret(&secret).unwrap().as_slice(), key);
    assert_eq!(decode_key_secret(b"netvfs-key-v1:YQ==").unwrap().as_slice(), b"a");
    for bad in [
        &b"netvfs-key-v1:"[..],
        b"netvfs-key-v1:YQ",
        b"netvfs-key-v1:YR==",
        b"netvfs-key-v1:Y Q==",
        b"netvfs-key-v1:%%%",
        b"netvfs-key-v2:YQ==",
        b"password",
        b"",
    ] {
        assert_eq!(decode_key_secret(bad), None, "{}", String::from_utf8_lossy(bad));
    }
    assert!(is_key_secret(b"netvfs-key-v1:"));
    assert!(!is_key_secret(b"netvfs-key-v"));
    assert!(!is_key_secret(b" netvfs-key-v1:YQ=="));
    assert_eq!(encode_key_secret(b"").as_slice(), b"netvfs-key-v1:");
}
