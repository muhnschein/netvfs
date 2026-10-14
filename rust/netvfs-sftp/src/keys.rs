// SPDX-License-Identifier: LGPL-2.1-or-later
//! SSH key tools (SPEC-sftp 5.1, S-15): generate an Ed25519 key, import
//! Ed25519 and ECDSA keys from OpenSSH (bcrypt-encrypted or not), PKCS#8
//! (PBES2-encrypted or not) and SEC1 files, and describe a stored key.
//! RSA and DSA keys, security keys, certificates, PuTTY files and PEM
//! files with the legacy (MD5) encryption are refused, by their armour
//! where it names them, else right after decoding; no private-key
//! operation runs on a refused key.

use data_encoding::BASE64;
use netvfs_vfs::{ErrorName, Status};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// The comment of the public line (SPEC-sftp 5.1).
pub const PUBLIC_KEY_COMMENT: &str = "sailfish-backup";
/// The prefix of a key stored as the account secret (SPEC-sftp 2).
pub const KEY_SECRET_PREFIX: &[u8] = b"netvfs-key-v1:";
/// Key files larger than this are not keys (a 16384-bit RSA key in PEM is
/// about 12 KiB).
pub const MAX_KEY_FILE: usize = 64 * 1024;

const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PKCS8_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_ENCRYPTED_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const SEC1_BEGIN: &str = "-----BEGIN EC PRIVATE KEY-----";
const RSA_BEGIN: &str = "-----BEGIN RSA PRIVATE KEY-----";
const DSA_BEGIN: &str = "-----BEGIN DSA PRIVATE KEY-----";
/// The OID of DSA (1.2.840.10040.4.1), which PKCS#8 names only inside.
const DSA_OID: &str = "1.2.840.10040.4.1";

/// `SshKeyMaterial`: the private key unencrypted in OpenSSH format, its
/// algorithm, the public line and the fingerprint.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    /// Unencrypted, OpenSSH format; wiped when this goes.
    pub private_key: Zeroizing<Vec<u8>>,
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, ...
    pub algorithm: String,
    /// `<algorithm> <base64> sailfish-backup`.
    pub public_line: String,
    /// `SHA256:` and unpadded base64, as `ssh-keygen -lf` prints it.
    pub fingerprint: String,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

fn not_a_key() -> Status {
    Status::unsupported("The file is not a private key in OpenSSH or PEM format")
}

fn unusable() -> Status {
    Status::unsupported("The file is not a key this app can use (Ed25519 or ECDSA in OpenSSH or PEM format)")
}

fn rsa_refused() -> Status {
    Status::unsupported("RSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key")
}

fn dsa_refused() -> Status {
    Status::unsupported("DSA keys are not supported; generate a new key, or use an Ed25519 or ECDSA key")
}

fn legacy_encryption_refused() -> Status {
    Status::unsupported("Keys encrypted in the legacy PEM format are not supported; generate a new key")
}

fn security_key_refused() -> Status {
    Status::unsupported("Security-key (FIDO) keys are not supported")
}

fn certificate_refused() -> Status {
    Status::unsupported("SSH certificates are not supported; choose a private key file")
}

fn type_refused(key_type: &str) -> Status {
    Status::unsupported(format!(
        "Key type {key_type} is not supported; generate a new key, or use an Ed25519 or ECDSA key"
    ))
}

fn passphrase_needed() -> Status {
    Status::new(ErrorName::AuthFailed, "The key is protected by a passphrase")
}

fn wrong_passphrase() -> Status {
    Status::new(ErrorName::AuthFailed, "The passphrase is not correct")
}

/// S-15: only Ed25519 and ECDSA on the NIST curves.
///
/// # Errors
/// `Unsupported`, naming what is refused.
pub fn check_algorithm(algorithm: &Algorithm) -> Result<(), Status> {
    match algorithm {
        Algorithm::Ed25519
        | Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384 | EcdsaCurve::NistP521 } => {
            Ok(())
        }
        Algorithm::Rsa { .. } => Err(rsa_refused()),
        Algorithm::Dsa => Err(dsa_refused()),
        Algorithm::SkEcdsaSha2NistP256 | Algorithm::SkEd25519 => Err(security_key_refused()),
        other => Err(type_refused(other.as_str())),
    }
}

/// The armour of a key file: what its first `-----BEGIN` line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Armour {
    OpenSsh,
    Pkcs8,
    Pkcs8Encrypted,
    Sec1,
}

/// Refusals that the text shows without decoding anything.
fn armour(text: &str) -> Result<Armour, Status> {
    let trimmed = text.trim_start();
    if trimmed.starts_with("PuTTY-User-Key-File-") {
        return Err(not_a_key());
    }
    let Some(begin) = text.lines().map(str::trim).find(|l| l.starts_with("-----BEGIN ")) else {
        return Err(public_line_refusal(trimmed).unwrap_or_else(not_a_key));
    };
    match begin {
        OPENSSH_BEGIN => Ok(Armour::OpenSsh),
        RSA_BEGIN => Err(rsa_refused()),
        DSA_BEGIN => Err(dsa_refused()),
        _ if text.lines().any(|l| l.trim() == "Proc-Type: 4,ENCRYPTED") => Err(legacy_encryption_refused()),
        PKCS8_BEGIN => Ok(Armour::Pkcs8),
        PKCS8_ENCRYPTED_BEGIN => Ok(Armour::Pkcs8Encrypted),
        SEC1_BEGIN => Ok(Armour::Sec1),
        _ => Err(not_a_key()),
    }
}

/// A public key or certificate line (`<type> AAAA... [comment]`).
fn public_line_refusal(text: &str) -> Option<Status> {
    let mut fields = text.split_ascii_whitespace();
    let key_type = fields.next()?;
    if !fields.next()?.starts_with("AAAA") {
        return None;
    }
    if key_type.ends_with("-cert-v01@openssh.com") {
        return Some(certificate_refused());
    }
    Some(Status::unsupported("This is a public key; choose the private key file"))
}

/// The private key in `file`, decrypted with `passphrase` when it is
/// encrypted.
///
/// # Errors
/// `Unsupported` for files and keys S-15 refuses; `AuthFailed` for a
/// missing or wrong passphrase.
pub fn read_private_key(file: &[u8], passphrase: &[u8]) -> Result<PrivateKey, Status> {
    if file.len() > MAX_KEY_FILE {
        return Err(not_a_key());
    }
    // Pasted keys may come with blank lines or spaces around them.
    let text = std::str::from_utf8(file).map_err(|_not_text| not_a_key())?.trim();
    let key = match armour(text)? {
        Armour::OpenSsh => {
            let key = PrivateKey::from_openssh(text).map_err(|e| match e {
                russh::keys::ssh_key::Error::AlgorithmUnknown => type_refused("(unknown)"),
                _ => unusable(),
            })?;
            // The public half is not encrypted: refused before the
            // passphrase is asked for.
            check_algorithm(&key.algorithm())?;
            if key.is_encrypted() {
                if passphrase.is_empty() {
                    return Err(passphrase_needed());
                }
                key.decrypt(passphrase).map_err(|e| match e {
                    russh::keys::ssh_key::Error::Crypto => wrong_passphrase(),
                    _ => unusable(),
                })?
            } else {
                key
            }
        }
        Armour::Pkcs8Encrypted => {
            if passphrase.is_empty() {
                return Err(passphrase_needed());
            }
            let Ok(passphrase) = std::str::from_utf8(passphrase) else {
                return Err(wrong_passphrase());
            };
            russh::keys::decode_secret_key(text, Some(passphrase)).map_err(|e| match e {
                russh::keys::Error::Pkcs8(_) => wrong_passphrase(),
                other => decoding_failure(&other),
            })?
        }
        // russh takes a password as the sign of the encrypted format:
        // never one here.
        Armour::Pkcs8 | Armour::Sec1 => {
            russh::keys::decode_secret_key(text, None).map_err(|e| decoding_failure(&e))?
        }
    };
    check_algorithm(&key.algorithm())?;
    Ok(key)
}

/// A PKCS#8 or SEC1 key russh could not read.
fn decoding_failure(e: &russh::keys::Error) -> Status {
    match e {
        russh::keys::Error::UnknownAlgorithm(oid) if oid.to_string() == DSA_OID => dsa_refused(),
        russh::keys::Error::UnknownAlgorithm(oid) => type_refused(&oid.to_string()),
        _ => unusable(),
    }
}

/// The material of an accepted, decrypted key.
///
/// # Errors
/// `Internal` when the key cannot be written out (not for keys this
/// module read or made).
pub fn material(key: &PrivateKey) -> Result<KeyMaterial, Status> {
    let mut plain = key.clone();
    plain.set_comment("");
    let private_key =
        plain.to_openssh(LineEnding::LF).map_err(|_e| Status::internal("Cannot export the private key"))?;
    let public = key.public_key();
    let blob = public.to_bytes().map_err(|_e| Status::internal("Cannot export the public key"))?;
    let algorithm = public.algorithm().as_str().to_owned();
    Ok(KeyMaterial {
        private_key: Zeroizing::new(private_key.as_bytes().to_vec()),
        public_line: format!("{algorithm} {} {PUBLIC_KEY_COMMENT}", BASE64.encode(&blob)),
        fingerprint: fingerprint(public),
        algorithm,
    })
}

/// `SHA256:` and unpadded base64 (S-6), as `ssh-keygen -lf` prints it.
#[must_use]
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// `SshKeyTools::generate`: a new Ed25519 key.
///
/// # Errors
/// `Internal` when the system has no randomness to give.
pub fn generate() -> Result<KeyMaterial, Status> {
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
        .map_err(|_e| Status::internal("Key generation failed"))?;
    material(&key)
}

/// `SshKeyTools::importKey`.
///
/// # Errors
/// As [`read_private_key`].
pub fn import(file: &[u8], passphrase: &[u8]) -> Result<KeyMaterial, Status> {
    material(&read_private_key(file, passphrase)?)
}

/// `SshKeyTools::describe`: the material of a stored (unencrypted) key.
///
/// # Errors
/// As [`read_private_key`] without a passphrase.
pub fn describe(private_key: &[u8]) -> Result<KeyMaterial, Status> {
    import(private_key, b"")
}

/// Whether `secret` is a key secret (`netvfs-key-v1:`), valid or not.
#[must_use]
pub fn is_key_secret(secret: &[u8]) -> bool {
    secret.starts_with(KEY_SECRET_PREFIX)
}

/// The private key of a key secret: canonical, padded base64 of at least
/// one byte after the prefix; `None` otherwise.
#[must_use]
pub fn decode_key_secret(secret: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let encoded = secret.strip_prefix(KEY_SECRET_PREFIX)?;
    let decoded = Zeroizing::new(BASE64.decode(encoded).ok()?);
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

/// The key secret of `private_key`.
#[must_use]
pub fn encode_key_secret(private_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let length = KEY_SECRET_PREFIX.len().saturating_add(BASE64.encode_len(private_key.len()));
    let mut secret = Zeroizing::new(vec![0; length]);
    let (prefix, encoded) = secret.split_at_mut(KEY_SECRET_PREFIX.len());
    prefix.copy_from_slice(KEY_SECRET_PREFIX);
    BASE64.encode_mut(private_key, encoded);
    secret
}

#[cfg(test)]
mod tests;
