// SPDX-License-Identifier: LGPL-2.1-or-later
//! The SMB 3.1.1 crypto glue (phase 3 design §5.2). This is the only module
//! that imports a RustCrypto crate or the OS random generator
//! (`tools/ci/check-crypto-fence.sh`), and it holds no primitive, no table
//! and no constant-time code of its own: hashing, HMAC, CMAC, AES-GCM and
//! every tag comparison are RustCrypto's.
//!
//! What MS-SMB2 mandates on top of the primitives, and nothing else:
//! - [`PreauthHash`]: H = SHA-512(H ‖ message) over NEGOTIATE and
//!   SESSION_SETUP (MS-SMB2 3.2.5.2, 3.2.5.3.1).
//! - [`kdf`]: SP800-108 counter mode with HMAC-SHA256, one block
//!   (MS-SMB2 3.1.4.2).
//! - [`SigningKey`]: AES-128-CMAC over the message with the signature field
//!   zeroed; the comparison is `cmac`'s `verify_slice` (`subtle`), never
//!   `==` (MS-SMB2 3.1.4.1).
//! - [`SealKey`] and [`OpenKey`]: AES-128/256-GCM in a TRANSFORM_HEADER,
//!   nonce = 64-bit per-session counter ‖ 4 random bytes, AAD = header bytes
//!   20..52, tag in the header's Signature field (MS-SMB2 2.2.41, 3.1.4.3).
//! - [`random`]: the OS generator, for the nonce salt, ClientGuid and the
//!   preauth salt.

use std::fmt;
use std::ops::Range;

use aes::Aes128;
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Tag};
use cmac::{Cmac, Mac};
use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// Length of the preauth integrity hash (SHA-512).
pub const PREAUTH_HASH_LEN: usize = 64;
/// Label of the signing key, with its terminating NUL (MS-SMB2 3.2.5.3.1).
pub const LABEL_SIGNING: &[u8] = b"SMBSigningKey\0";
/// Label of the client-to-server cipher key.
pub const LABEL_C2S_CIPHER: &[u8] = b"SMBC2SCipherKey\0";
/// Label of the server-to-client cipher key.
pub const LABEL_S2C_CIPHER: &[u8] = b"SMBS2CCipherKey\0";
/// Size of the SMB2 TRANSFORM_HEADER.
pub const TRANSFORM_HEADER_LEN: usize = 52;
/// ProtocolId of a TRANSFORM_HEADER.
pub const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];

/// Where the 16-byte signature lives in an SMB2 header.
const SIGNATURE: Range<usize> = 48..64;
/// TRANSFORM_HEADER layout (MS-SMB2 2.2.41).
const TH_TAG: Range<usize> = 4..20;
const TH_NONCE: Range<usize> = 20..32;
const TH_AAD: Range<usize> = 20..52;
const TH_SIZE: Range<usize> = 36..40;
const TH_FLAGS: Range<usize> = 42..44;
const TH_SESSION: Range<usize> = 44..52;
/// Flags (3.1.1): "encrypted".
const TH_FLAG_ENCRYPTED: u16 = 0x0001;

/// A failure in the glue. Every variant means the message must not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// AES-CMAC signature mismatch.
    BadSignature,
    /// AES-GCM tag mismatch: key, nonce, AAD, tag or ciphertext altered.
    Unauthentic,
    /// TRANSFORM_HEADER malformed.
    Malformed(&'static str),
    /// TRANSFORM_HEADER for a session we do not have.
    WrongSession,
    /// The nonce counter is used up; the session must end.
    NonceExhausted,
    /// Message shorter than an SMB2 header.
    ShortMessage,
    /// Key material of the wrong length.
    KeyLength,
    /// The OS random generator failed.
    NoRandomness,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => f.write_str("message signature does not verify"),
            Self::Unauthentic => f.write_str("encrypted message does not authenticate"),
            Self::Malformed(m) => write!(f, "malformed transform header: {m}"),
            Self::WrongSession => f.write_str("encrypted message for an unknown session"),
            Self::NonceExhausted => f.write_str("encryption nonce counter exhausted"),
            Self::ShortMessage => f.write_str("message shorter than an SMB2 header"),
            Self::KeyLength => f.write_str("key of the wrong length"),
            Self::NoRandomness => f.write_str("the OS random generator failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Fills `buf` from the OS random generator (`getrandom`): the nonce salt,
/// and NEGOTIATE's ClientGuid and preauth salt (MS-SMB2 2.2.3, 2.2.3.1.1).
///
/// # Errors
/// [`CryptoError::NoRandomness`] when the OS generator fails.
pub fn random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_getrandom_error| CryptoError::NoRandomness)
}

// ---------------------------------------------------------------------------
// Preauth integrity
// ---------------------------------------------------------------------------

/// The SMB 3.1.1 preauth integrity hash value (SHA-512 chain; starts as 64
/// zero bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct PreauthHash([u8; PREAUTH_HASH_LEN]);

impl Default for PreauthHash {
    fn default() -> Self {
        Self([0; PREAUTH_HASH_LEN])
    }
}

impl PreauthHash {
    /// H = SHA-512(H ‖ message), over the whole SMB2 message as sent or
    /// received (header included, transport length excluded).
    pub fn update(&mut self, message: &[u8]) {
        self.0 = Sha512::new().chain_update(self.0).chain_update(message).finalize().into();
    }

    /// The current value.
    #[must_use]
    pub fn value(&self) -> &[u8; PREAUTH_HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for PreauthHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreauthHash(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// SP800-108 KDF in counter mode, PRF HMAC-SHA256, r = 32, as MS-SMB2
/// 3.1.4.2 uses it: `K = HMAC-SHA256(key, [1]₃₂ ‖ label ‖ 0x00 ‖ context ‖
/// [L]₃₂)`, truncated to L bits. One PRF block suffices because L ≤ 256.
/// `N` is 16 (L = 128) or 32 (L = 256).
///
/// # Errors
/// [`CryptoError::KeyLength`] for any other `N` or an empty key.
pub fn kdf<const N: usize>(
    key: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let bits: u32 = match N {
        16 => 128,
        32 => 256,
        _ => return Err(CryptoError::KeyLength),
    };
    if key.is_empty() {
        return Err(CryptoError::KeyLength);
    }
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_invalid_length| CryptoError::KeyLength)?;
    Mac::update(&mut mac, &1u32.to_be_bytes());
    Mac::update(&mut mac, label);
    Mac::update(&mut mac, &[0]);
    Mac::update(&mut mac, context);
    Mac::update(&mut mac, &bits.to_be_bytes());
    let block: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(block.get(..N).ok_or(CryptoError::KeyLength)?);
    Ok(out)
}

/// A negotiated cipher; only the GCM pair is ever offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128-GCM, cipher id 0x0002.
    Aes128Gcm,
    /// AES-256-GCM, cipher id 0x0004.
    Aes256Gcm,
}

/// The keys of one authenticated session (MS-SMB2 3.2.5.3.1).
#[derive(Debug)]
pub struct SessionKeys {
    /// Signs requests and verifies responses.
    pub signing: SigningKey,
    /// Encrypts requests (client-to-server key); absent without a cipher.
    pub seal: Option<SealKey>,
    /// Decrypts responses (server-to-client key); absent without a cipher.
    pub open: Option<OpenKey>,
}

/// `Session.SessionKey`: the first 16 bytes of the GSS key, right-padded
/// with zeros.
fn session_key(gss_key: &[u8]) -> Zeroizing<[u8; 16]> {
    let mut key = Zeroizing::new([0u8; 16]);
    for (d, s) in key.iter_mut().zip(gss_key) {
        *d = *s;
    }
    key
}

/// The GCM key for one direction: AES-128 keys come from `Session.SessionKey`
/// with L = 128, AES-256 keys from `Session.FullSessionKey` (the whole GSS
/// key) with L = 256.
fn gcm_key(gss_key: &[u8], cipher: Cipher, label: &[u8], context: &[u8]) -> Result<GcmKey, CryptoError> {
    Ok(match cipher {
        Cipher::Aes128Gcm => GcmKey::Aes128(kdf::<16>(&session_key(gss_key)[..], label, context)?),
        Cipher::Aes256Gcm => GcmKey::Aes256(kdf::<32>(gss_key, label, context)?),
    })
}

/// Derives the session's keys from the GSS (NTLM) session key and the
/// session's final preauth hash.
///
/// # Errors
/// [`CryptoError::KeyLength`] for an empty GSS key;
/// [`CryptoError::NoRandomness`] when no nonce salt can be drawn.
pub fn derive_session_keys(
    gss_key: &[u8],
    preauth: &PreauthHash,
    cipher: Option<Cipher>,
    session_id: u64,
) -> Result<SessionKeys, CryptoError> {
    if gss_key.is_empty() {
        return Err(CryptoError::KeyLength);
    }
    let context = preauth.value();
    let signing = SigningKey(kdf::<16>(&session_key(gss_key)[..], LABEL_SIGNING, context)?);
    let (seal, open) = match cipher {
        None => (None, None),
        Some(cipher) => (
            Some(SealKey::new(gcm_key(gss_key, cipher, LABEL_C2S_CIPHER, context)?, session_id)?),
            Some(OpenKey { key: gcm_key(gss_key, cipher, LABEL_S2C_CIPHER, context)?, session_id }),
        ),
    };
    Ok(SessionKeys { signing, seal, open })
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// AES-128-CMAC signing key.
pub struct SigningKey(Zeroizing<[u8; 16]>);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl SigningKey {
    /// Wraps raw key bytes (known-answer vectors, fuzzing).
    #[must_use]
    pub fn from_bytes(key: [u8; 16]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn mac(&self) -> Result<Cmac<Aes128>, CryptoError> {
        <Cmac<Aes128> as KeyInit>::new_from_slice(&self.0[..])
            .map_err(|_invalid_length| CryptoError::KeyLength)
    }

    /// Signs one SMB2 message in place: zeroes the Signature field, computes
    /// AES-CMAC over the whole message (header with SMB2_FLAGS_SIGNED
    /// already set, then body) and stores it.
    ///
    /// # Errors
    /// [`CryptoError::ShortMessage`] if `msg` has no complete header.
    pub fn sign(&self, msg: &mut [u8]) -> Result<(), CryptoError> {
        msg.get_mut(SIGNATURE).ok_or(CryptoError::ShortMessage)?.fill(0);
        let mut mac = self.mac()?;
        mac.update(msg);
        let tag = mac.finalize().into_bytes();
        msg.get_mut(SIGNATURE).ok_or(CryptoError::ShortMessage)?.copy_from_slice(&tag);
        Ok(())
    }

    /// Verifies the signature of one SMB2 message without changing it: the
    /// MAC runs over the header with the Signature field taken as zeros, and
    /// the comparison is constant time.
    ///
    /// # Errors
    /// [`CryptoError::BadSignature`] on mismatch,
    /// [`CryptoError::ShortMessage`] without a complete header.
    pub fn verify(&self, msg: &[u8]) -> Result<(), CryptoError> {
        let head = msg.get(..SIGNATURE.start).ok_or(CryptoError::ShortMessage)?;
        let signature = msg.get(SIGNATURE).ok_or(CryptoError::ShortMessage)?;
        let tail = msg.get(SIGNATURE.end..).ok_or(CryptoError::ShortMessage)?;
        let mut mac = self.mac()?;
        mac.update(head);
        mac.update(&[0u8; 16]);
        mac.update(tail);
        mac.verify_slice(signature).map_err(|_mac_error| CryptoError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// GCM key bytes for one direction.
enum GcmKey {
    Aes128(Zeroizing<[u8; 16]>),
    Aes256(Zeroizing<[u8; 32]>),
}

impl GcmKey {
    fn from_bytes(cipher: Cipher, key: &[u8]) -> Result<Self, CryptoError> {
        Ok(match cipher {
            Cipher::Aes128Gcm => {
                Self::Aes128(Zeroizing::new(key.try_into().map_err(|_wrong_length| CryptoError::KeyLength)?))
            }
            Cipher::Aes256Gcm => {
                Self::Aes256(Zeroizing::new(key.try_into().map_err(|_wrong_length| CryptoError::KeyLength)?))
            }
        })
    }

    fn cipher(&self) -> Cipher {
        match self {
            Self::Aes128(_) => Cipher::Aes128Gcm,
            Self::Aes256(_) => Cipher::Aes256Gcm,
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        let nonce = Nonce::from(*nonce);
        let tag = match self {
            Self::Aes128(k) => Aes128Gcm::new(&(**k).into()).encrypt_inout_detached(&nonce, aad, buf.into()),
            Self::Aes256(k) => Aes256Gcm::new(&(**k).into()).encrypt_inout_detached(&nonce, aad, buf.into()),
        }
        .map_err(|_aead_error| CryptoError::Malformed("message too long for GCM"))?;
        Ok(tag.into())
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let nonce = Nonce::from(*nonce);
        let tag = Tag::from(*tag);
        match self {
            Self::Aes128(k) => {
                Aes128Gcm::new(&(**k).into()).decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
            }
            Self::Aes256(k) => {
                Aes256Gcm::new(&(**k).into()).decrypt_inout_detached(&nonce, aad, buf.into(), &tag)
            }
        }
        .map_err(|_aead_error| CryptoError::Unauthentic)
    }
}

/// Encrypts the requests of one session (client-to-server key).
pub struct SealKey {
    key: GcmKey,
    session_id: u64,
    /// Next nonce counter value; the session ends before it wraps.
    counter: u64,
    /// Random per-session nonce bytes 8..12 (defence in depth on top of the
    /// counter).
    salt: [u8; 4],
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealKey")
            .field("cipher", &self.key.cipher())
            .field("session_id", &self.session_id)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SealKey {
    fn new(key: GcmKey, session_id: u64) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 4];
        random(&mut salt)?;
        Ok(Self { key, session_id, counter: 0, salt })
    }

    /// A key from raw bytes (a fake server's side in tests, fuzzing).
    ///
    /// # Errors
    /// [`CryptoError::KeyLength`] when `key` does not fit `cipher`;
    /// [`CryptoError::NoRandomness`].
    pub fn from_bytes(cipher: Cipher, key: &[u8], session_id: u64) -> Result<Self, CryptoError> {
        Self::new(GcmKey::from_bytes(cipher, key)?, session_id)
    }

    /// The cipher of this key.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        self.key.cipher()
    }

    /// Wraps `msg` (one SMB2 message or compound chain, unsigned) in a
    /// TRANSFORM_HEADER with the next nonce.
    ///
    /// # Errors
    /// [`CryptoError::NonceExhausted`] once the counter is used up: the
    /// caller must end the session then.
    pub fn seal(&mut self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let counter = self.counter;
        self.counter = counter.checked_add(1).ok_or(CryptoError::NonceExhausted)?;
        let mut nonce = [0u8; 12];
        for (d, s) in nonce.iter_mut().zip(counter.to_le_bytes().iter().chain(self.salt.iter())) {
            *d = *s;
        }
        self.seal_with_nonce(&nonce, msg)
    }

    /// The TRANSFORM_HEADER construction for a given 12-byte nonce. Private:
    /// nonces only come from [`Self::seal`]; known-answer tests call this.
    fn seal_with_nonce(&self, nonce: &[u8; 12], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let size =
            u32::try_from(msg.len()).map_err(|_overflow| CryptoError::Malformed("message too long"))?;
        let mut out = Vec::new();
        out.extend_from_slice(&TRANSFORM_PROTOCOL_ID);
        out.extend_from_slice(&[0u8; 16]); // Signature: the tag, filled in below
        out.extend_from_slice(nonce);
        out.extend_from_slice(&[0u8; 4]); // the rest of the 16-byte Nonce field
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&[0u8; 2]); // Reserved
        out.extend_from_slice(&TH_FLAG_ENCRYPTED.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(msg);
        let (header, body) = out.split_at_mut(TRANSFORM_HEADER_LEN);
        let tag = self.key.encrypt(nonce, header.get(TH_AAD).ok_or(CryptoError::ShortMessage)?, body)?;
        header.get_mut(TH_TAG).ok_or(CryptoError::ShortMessage)?.copy_from_slice(&tag);
        Ok(out)
    }
}

/// Decrypts the responses of one session (server-to-client key).
pub struct OpenKey {
    key: GcmKey,
    session_id: u64,
}

impl fmt::Debug for OpenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenKey")
            .field("cipher", &self.key.cipher())
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl OpenKey {
    /// A key from raw bytes (a fake server's side in tests, fuzzing).
    ///
    /// # Errors
    /// [`CryptoError::KeyLength`] when `key` does not fit `cipher`.
    pub fn from_bytes(cipher: Cipher, key: &[u8], session_id: u64) -> Result<Self, CryptoError> {
        Ok(Self { key: GcmKey::from_bytes(cipher, key)?, session_id })
    }

    /// Checks and decrypts one TRANSFORM_HEADER frame, returning the SMB2
    /// message(s) inside. Refuses a short frame, a wrong ProtocolId, Flags
    /// other than "encrypted", a session id other than ours and an
    /// OriginalMessageSize that does not match the frame, before any
    /// decryption; then GCM verifies the tag over the AAD (header bytes
    /// 20..52) and the ciphertext.
    ///
    /// # Errors
    /// See [`CryptoError`]; no plaintext is returned unless the tag verifies.
    pub fn open(&self, frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let header = frame.get(..TRANSFORM_HEADER_LEN).ok_or(CryptoError::Malformed("short frame"))?;
        let body = frame.get(TRANSFORM_HEADER_LEN..).ok_or(CryptoError::Malformed("short frame"))?;
        if header.get(..4) != Some(&TRANSFORM_PROTOCOL_ID[..]) {
            return Err(CryptoError::Malformed("not a transform header"));
        }
        if u16::from_le_bytes(field(header, TH_FLAGS)?) != TH_FLAG_ENCRYPTED {
            return Err(CryptoError::Malformed("flags are not 'encrypted'"));
        }
        if u64::from_le_bytes(field(header, TH_SESSION)?) != self.session_id {
            return Err(CryptoError::WrongSession);
        }
        let size = u32::from_le_bytes(field(header, TH_SIZE)?);
        if usize::try_from(size).ok() != Some(body.len()) {
            return Err(CryptoError::Malformed("OriginalMessageSize does not match the frame"));
        }
        let nonce: [u8; 12] = field(header, TH_NONCE)?;
        let tag: [u8; 16] = field(header, TH_TAG)?;
        let aad = header.get(TH_AAD).ok_or(CryptoError::ShortMessage)?;
        let mut plain = body.to_vec();
        self.key.decrypt(&nonce, aad, &mut plain, &tag)?;
        Ok(plain)
    }
}

/// The server's side of a session's keys (S2C sealing, C2S opening), for
/// fake servers in the tests of other modules.
#[cfg(test)]
pub(crate) fn server_side_keys(
    gss_key: &[u8],
    preauth: &PreauthHash,
    cipher: Cipher,
    session_id: u64,
) -> Result<(SealKey, OpenKey), CryptoError> {
    let context = preauth.value();
    Ok((
        SealKey::new(gcm_key(gss_key, cipher, LABEL_S2C_CIPHER, context)?, session_id)?,
        OpenKey { key: gcm_key(gss_key, cipher, LABEL_C2S_CIPHER, context)?, session_id },
    ))
}

fn field<const N: usize>(buf: &[u8], range: Range<usize>) -> Result<[u8; N], CryptoError> {
    buf.get(range).and_then(|b| b.try_into().ok()).ok_or(CryptoError::Malformed("short header"))
}

#[cfg(test)]
mod tests;
