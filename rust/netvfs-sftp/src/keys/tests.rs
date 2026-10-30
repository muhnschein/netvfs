// SPDX-License-Identifier: LGPL-2.1-or-later
//! Key files in `testdata/keys` were made with ssh-keygen (OpenSSH 9.6p1) and openssl 3.0.13; `golden.txt` holds
//! the expected outcome of each: Ed25519 and ECDSA keys must come out the same, byte for byte.

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
        // RSA keys and legacy encrypted PEM are refused whatever the passphrase.
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
                // The DSA message does not suggest RSA.
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

/// The length of the private scalar of an unencrypted OpenSSH ECDSA key
/// file, as stored (an SSH mpint: no leading zero bytes).
fn stored_scalar_len(file: &str) -> usize {
    /// The SSH string at the start of `data`, and what follows it.
    fn string(data: &[u8]) -> (&[u8], &[u8]) {
        let (len, rest) = data.split_at(4);
        rest.split_at(usize::try_from(u32::from_be_bytes(len.try_into().unwrap())).unwrap())
    }
    let text = String::from_utf8(fixture(file)).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let blob = BASE64.decode(body.as_bytes()).unwrap();
    let mut rest = blob.strip_prefix(b"openssh-key-v1\0").unwrap();
    for _ in 0..3 {
        rest = string(rest).1; // cipher, KDF, KDF options
    }
    rest = rest.split_at(4).1; // number of keys
    rest = string(rest).1; // public key
    let mut rest = string(rest).0.split_at(8).1; // the private part after its check bytes
    for _ in 0..3 {
        rest = string(rest).1; // key type, curve, public point
    }
    string(rest).0.len()
}

#[test]
fn p256_keys_with_a_short_scalar() {
    // ssh-keygen writes a P-256 scalar with a leading zero byte as 31 bytes
    // (about one key in 256); this key (OpenSSH 9.6p1, then `ssh-keygen -p`
    // for the encrypted copy) is one. rust/vendor/ssh-key reads it.
    assert_eq!(stored_scalar_len("ecdsa256-short-scalar"), 31);
    let pub_file = String::from_utf8(fixture("ecdsa256-short-scalar.pub")).unwrap();
    let blob = pub_file.split_whitespace().nth(1).unwrap();
    for (file, passphrase) in [("ecdsa256-short-scalar", &b""[..]), ("ecdsa256-short-scalar-enc", PASSPHRASE)]
    {
        let key = read_private_key(&fixture(file), passphrase).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        let Some(russh::keys::ssh_key::private::EcdsaKeypair::NistP256 { private, .. }) =
            key.key_data().ecdsa()
        else {
            panic!("{file}: not a P-256 key");
        };
        assert_eq!(private.as_slice()[0], 0, "{file}: the scalar is padded to 32 bytes");
        let material = material(&key).unwrap();
        assert_eq!(material.algorithm, "ecdsa-sha2-nistp256");
        assert_eq!(material.public_line, format!("ecdsa-sha2-nistp256 {blob} sailfish-backup"));
        // `ssh-keygen -lf ecdsa256-short-scalar.pub`.
        assert_eq!(material.fingerprint, "SHA256:eHNCT7aZVPJ7aBziwLCZ5kCrJrZ99PG/sVG9z//cpwo");
        // The key signs, and its public key verifies the signature.
        let signature = key.sign("netvfs", HashAlg::Sha256, b"message").unwrap();
        key.public_key().verify("netvfs", b"message", &signature).unwrap();
        assert!(key.public_key().verify("netvfs", b"massage", &signature).is_err());
        // The stored form (the scalar written back as 32 bytes) reads again.
        assert_eq!(describe(&material.private_key).unwrap(), material);
    }
    assert_eq!(refusal(import(&fixture("ecdsa256-short-scalar-enc"), WRONG)), auth(NOT_CORRECT));
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

const TOO_COSTLY: &str =
    "Opening this key would take too long; protect it with fewer rounds, or generate a new key";

/// `file` (an encrypted OpenSSH key) with its bcrypt rounds set to
/// `rounds`: the field after the kdf name and the salt, a fixed-width
/// `uint32`, so nothing else moves.
fn with_bcrypt_rounds(file: &str, rounds: u32) -> Vec<u8> {
    with_openssh_blob(file, |blob| {
        let plus = |a: usize, b: usize| a.checked_add(b).unwrap();
        let kdf = plus(blob.windows(6).position(|w| w == b"bcrypt").unwrap(), 6);
        // uint32 length of the options, then the salt (uint32 length + bytes).
        let salt_len = u32::from_be_bytes(blob[plus(kdf, 4)..plus(kdf, 8)].try_into().unwrap());
        let at = plus(plus(kdf, 8), usize::try_from(salt_len).unwrap());
        let field = at..plus(at, 4);
        assert_eq!(
            u32::from_be_bytes(blob[field.clone()].try_into().unwrap()),
            24,
            "ssh-keygen's default rounds"
        );
        blob[field].copy_from_slice(&rounds.to_be_bytes());
    })
}

/// `file` (an OpenSSH key) with its binary form changed by `change`.
fn with_openssh_blob(file: &str, change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let text = String::from_utf8(fixture(file)).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut blob = BASE64.decode(body.as_bytes()).unwrap();
    change(&mut blob);
    let encoded = BASE64.encode(&blob);
    let lines: Vec<&str> = encoded.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("{OPENSSH_BEGIN}\n{}\n-----END OPENSSH PRIVATE KEY-----\n", lines.join("\n")).into_bytes()
}

/// `file` (an encrypted PKCS#8 key) with its PBES2 parameters changed.
fn with_pbes2(file: &str, change: impl FnOnce(&mut pbes2::Parameters)) -> Vec<u8> {
    use pkcs8::der::EncodePem;
    let text = String::from_utf8(fixture(file)).unwrap();
    let (_label, document) = pkcs8::SecretDocument::from_pem(&text).unwrap();
    let mut info = document.decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>().unwrap();
    let EncryptionScheme::Pbes2(parameters) = &mut info.encryption_algorithm else {
        panic!("{file} is not PBES2");
    };
    change(parameters);
    info.to_pem(LineEnding::LF).unwrap().into_bytes()
}

#[test]
fn keys_too_costly_to_open_are_refused_before_the_passphrase() {
    // Made by ssh-keygen -a 1025, and by openssl with 1000001 PBKDF2
    // iterations and with scrypt p = 5: refused whatever the passphrase.
    for file in ["ed25519-openssh-rounds1025", "ecdsa256-pkcs8-iter1000001", "ecdsa256-pkcs8-scrypt-p5"] {
        for passphrase in [PASSPHRASE, b"", WRONG] {
            assert_eq!(refusal(import(&fixture(file), passphrase)), unsupported(TOO_COSTLY), "{file}");
        }
    }
    // At the bound the passphrase is asked for (none given: no key
    // derivation runs), past it the key is refused.
    let bcrypt = |rounds| refusal(import(&with_bcrypt_rounds("ed25519-openssh-enc", rounds), b""));
    assert_eq!(bcrypt(MAX_BCRYPT_ROUNDS), auth(PROTECTED));
    assert_eq!(bcrypt(MAX_BCRYPT_ROUNDS + 1), unsupported(TOO_COSTLY));
    assert_eq!(bcrypt(u32::MAX), unsupported(TOO_COSTLY));
    let pbkdf2 = |iterations| {
        let file = with_pbes2("ecdsa256-pkcs8-enc", |p| {
            let pbes2::Kdf::Pbkdf2(kdf) = &mut p.kdf else { panic!("not PBKDF2") };
            kdf.iteration_count = iterations;
        });
        refusal(import(&file, b""))
    };
    assert_eq!(pbkdf2(MAX_PBKDF2_ITERATIONS), auth(PROTECTED));
    assert_eq!(pbkdf2(MAX_PBKDF2_ITERATIONS + 1), unsupported(TOO_COSTLY));
    let scrypt = |n: u64, r: u16, p: u16| {
        let file = with_pbes2("ecdsa256-pkcs8-scrypt", |params| {
            let pbes2::Kdf::Scrypt(kdf) = &mut params.kdf else { panic!("not scrypt") };
            (kdf.cost_parameter, kdf.block_size, kdf.parallelization) = (n, r, p);
        });
        refusal(import(&file, b""))
    };
    // 128 · r · N bytes: 64 MiB is the bound, by N or by r.
    assert_eq!(scrypt(1 << 16, 8, 1), auth(PROTECTED));
    assert_eq!(scrypt(1 << 17, 8, 1), unsupported(TOO_COSTLY));
    assert_eq!(scrypt(1 << 14, 32, 1), auth(PROTECTED));
    assert_eq!(scrypt(1 << 14, 33, 1), unsupported(TOO_COSTLY));
    assert_eq!(scrypt(u64::MAX, u16::MAX, 1), unsupported(TOO_COSTLY));
    assert_eq!(scrypt(1 << 14, 8, MAX_SCRYPT_PARALLELISM), auth(PROTECTED));
    assert_eq!(scrypt(1 << 14, 8, MAX_SCRYPT_PARALLELISM + 1), unsupported(TOO_COSTLY));
    // The files themselves are within the bounds (openssl's defaults).
    for file in ["ed25519-openssh-enc", "ecdsa256-pkcs8-enc", "ecdsa256-pkcs8-scrypt"] {
        assert_eq!(refusal(import(&fixture(file), b"")), auth(PROTECTED), "{file}");
    }
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
        ("dsa-pem-traditional", b"", unsupported(DSA)),
        (
            "ed448-pkcs8-openssl",
            b"",
            unsupported(
                "Key type 1.3.101.113 is not supported; generate a new key, or use an Ed25519 or ECDSA key",
            ),
        ),
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
fn ecdsa_keys_whose_curve_is_not_their_points_are_unusable() {
    // The curve names (length-prefixed) in the public key and the private
    // section; the point stays a P-384 one.
    let p256 = with_openssh_blob("ecdsa384-openssh", |blob| {
        let (from, to) = (b"\0\0\0\x08nistp384", b"\0\0\0\x08nistp256");
        assert_eq!(blob.windows(from.len()).filter(|w| *w == from).count(), 2);
        while let Some(at) = blob.windows(from.len()).position(|w| w == from) {
            blob[at..at.checked_add(from.len()).unwrap()].copy_from_slice(to);
        }
    });
    assert_eq!(refusal(import(&p256, b"")), unsupported(UNUSABLE));
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
