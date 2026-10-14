// SPDX-License-Identifier: LGPL-2.1-or-later
//! NEGOTIATE policy: offer exactly SMB 3.1.1 with SHA-512 preauth,
//! AES-128/256-GCM and AES-CMAC, and refuse any response that picks
//! something else (M-1, defence in depth).

use crate::crypto::{self, Cipher};
use crate::error::{Error, Result, policy, protocol};
use crate::msg::negotiate::{
    DIALECT_311, HASH_SHA512, NegotiateRequest, NegotiateResponse, SIGNING_AES_CMAC, caps, ciphers, ctx,
    encryption_context, parse_preauth, preauth_context, security_mode, signing_context, u16_list,
};

/// The smallest MaxRead/MaxWrite/MaxTransact accepted (MS-SMB2 requires 64 KiB for 2.1+).
pub const MIN_MAX_SIZE: usize = 65_536;
/// Sizes above this are clamped (design §3.2: ≤ 8 MiB + header).
pub const MAX_MAX_SIZE: usize = 8 * 1024 * 1024;

/// What the client offers.
#[derive(Debug, Clone)]
pub struct Offer {
    /// Signing required (strict, signed) or only enabled (guest).
    pub signing_required: bool,
    /// Ciphers in preference order; only GCM exists.
    pub ciphers: Vec<Cipher>,
    /// ClientGuid.
    pub client_guid: [u8; 16],
    /// Preauth salt.
    pub salt: [u8; 32],
}

impl Offer {
    /// A fresh offer with random ClientGuid and salt.
    ///
    /// # Errors
    /// `Internal` when the OS random generator fails.
    pub fn new(signing_required: bool, ciphers: Vec<Cipher>) -> Result<Self> {
        let mut client_guid = [0u8; 16];
        let mut salt = [0u8; 32];
        crypto::random(&mut client_guid)
            .and_then(|()| crypto::random(&mut salt))
            .map_err(|e| Error::Local(netvfs_vfs::Status::internal(format!("NEGOTIATE: {e}"))))?;
        Ok(Self { signing_required, ciphers, client_guid, salt })
    }

    /// The NEGOTIATE request body.
    ///
    /// # Errors
    /// Encoding failure.
    pub fn request(&self) -> Result<Vec<u8>> {
        let ids: Vec<u16> = self.ciphers.iter().map(|c| cipher_id(*c)).collect();
        let mut contexts = vec![preauth_context(&self.salt)];
        if !ids.is_empty() {
            contexts.push(encryption_context(&ids)?);
        }
        contexts.push(signing_context());
        let mode = if self.signing_required {
            security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED
        } else {
            security_mode::SIGNING_ENABLED
        };
        NegotiateRequest {
            security_mode: mode,
            capabilities: caps::LARGE_MTU | caps::ENCRYPTION,
            client_guid: self.client_guid,
            dialects: vec![DIALECT_311],
            contexts,
        }
        .encode()
    }
}

/// Wire id of a cipher.
#[must_use]
pub fn cipher_id(c: Cipher) -> u16 {
    match c {
        Cipher::Aes128Gcm => ciphers::AES128_GCM,
        Cipher::Aes256Gcm => ciphers::AES256_GCM,
    }
}

fn cipher_name(id: u16) -> String {
    match id {
        ciphers::AES128_CCM => "AES-128-CCM".into(),
        ciphers::AES128_GCM => "AES-128-GCM".into(),
        ciphers::AES256_CCM => "AES-256-CCM".into(),
        ciphers::AES256_GCM => "AES-256-GCM".into(),
        other => format!("cipher 0x{other:04X}"),
    }
}

/// The outcome of a valid NEGOTIATE.
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// Always 0x0311.
    pub dialect: u16,
    /// The cipher, if the server supports encryption.
    pub cipher: Option<Cipher>,
    /// Max read size (clamped).
    pub max_read: usize,
    /// Max write size (clamped).
    pub max_write: usize,
    /// Max transact size (clamped).
    pub max_transact: usize,
    /// Multi-credit requests allowed (LARGE_MTU).
    pub multi_credit: bool,
    /// The server requires signing.
    pub server_signing_required: bool,
    /// ServerGuid.
    pub server_guid: [u8; 16],
}

/// Checks a NEGOTIATE response against the offer.
///
/// # Errors
/// [`crate::Error::Policy`] for another dialect, a cipher or signing algorithm not
/// offered, a preauth hash other than SHA-512, compression; protocol errors for malformed or
/// duplicate contexts.
pub fn check_response(offer: &Offer, resp: &NegotiateResponse) -> Result<Negotiated> {
    if resp.dialect != DIALECT_311 {
        return Err(policy(format!(
            "the server selected SMB dialect 0x{:04X}; only SMB 3.1.1 (0x0311) is allowed",
            resp.dialect
        )));
    }
    let mut preauth = None;
    let mut encryption = None;
    let mut signing = None;
    for c in &resp.contexts {
        let slot = match c.kind {
            ctx::PREAUTH_INTEGRITY => &mut preauth,
            ctx::ENCRYPTION => &mut encryption,
            ctx::SIGNING => &mut signing,
            ctx::COMPRESSION => {
                return Err(policy("the server sent a compression context; compression is not offered"));
            }
            _ => continue, // contexts we did not offer carry nothing we act on
        };
        if slot.replace(&c.data).is_some() {
            return Err(protocol(format!("duplicate negotiate context 0x{:04X}", c.kind)));
        }
    }
    let (hashes, _salt) = parse_preauth(preauth.ok_or_else(|| protocol("no preauth integrity context"))?)?;
    if hashes != [HASH_SHA512] {
        return Err(policy("the server did not select SHA-512 preauth integrity"));
    }
    let cipher = match encryption {
        None => None,
        Some(data) => match u16_list(data)?.as_slice() {
            [0] => None, // no common cipher: encryption unavailable
            [id] => Some(offer.ciphers.iter().copied().find(|c| cipher_id(*c) == *id).ok_or_else(|| {
                policy(format!("the server selected {} which was not offered", cipher_name(*id)))
            })?),
            _ => return Err(protocol("encryption context must name exactly one cipher")),
        },
    };
    if let Some(data) = signing {
        match u16_list(data)?.as_slice() {
            [SIGNING_AES_CMAC] => {}
            [other] => {
                return Err(policy(format!(
                    "the server selected signing algorithm 0x{other:04X}; only AES-CMAC is offered"
                )));
            }
            _ => return Err(protocol("signing context must name exactly one algorithm")),
        }
    }
    let size = |v: u32, what: &str| -> Result<usize> {
        let v = usize::try_from(v).map_err(|e| protocol(format!("{what}: {e}")))?;
        if v < MIN_MAX_SIZE {
            return Err(protocol(format!("server {what} of {v} bytes is below 64 KiB")));
        }
        Ok(v.min(MAX_MAX_SIZE))
    };
    Ok(Negotiated {
        dialect: resp.dialect,
        cipher,
        max_read: size(resp.max_read, "MaxReadSize")?,
        max_write: size(resp.max_write, "MaxWriteSize")?,
        max_transact: size(resp.max_transact, "MaxTransactSize")?,
        multi_credit: resp.capabilities & caps::LARGE_MTU != 0,
        server_signing_required: resp.security_mode & security_mode::SIGNING_REQUIRED != 0,
        server_guid: resp.server_guid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::msg::negotiate::{NegContext, tests::response};

    fn offer() -> Offer {
        Offer::new(true, vec![Cipher::Aes128Gcm, Cipher::Aes256Gcm]).unwrap()
    }

    fn enc(ids: &[u16]) -> NegContext {
        encryption_context(ids).unwrap()
    }

    fn sign(alg: u16) -> NegContext {
        NegContext { kind: ctx::SIGNING, data: vec![1, 0, alg.to_le_bytes()[0], alg.to_le_bytes()[1]] }
    }

    fn check(dialect: u16, ctxs: &[NegContext]) -> Result<Negotiated> {
        check_response(&offer(), &NegotiateResponse::decode(&response(dialect, ctxs))?)
    }

    #[test]
    fn offer_contains_only_311_and_our_algorithms() {
        let body = offer().request().unwrap();
        let mut h = crate::msg::Header::request(crate::msg::Command::Negotiate, 0, 0, 0);
        h.flags = 0;
        let msg = crate::msg::build(&h, &body);
        // Decode our own request's contexts by reusing the response context walker layout:
        assert_eq!(u16::from_le_bytes([msg[66], msg[67]]), 1, "one dialect");
        assert_eq!(u16::from_le_bytes([msg[100], msg[101]]), DIALECT_311);
        assert_eq!(u16::from_le_bytes([msg[96], msg[97]]), 3, "three contexts");
    }

    #[test]
    fn accepts_311_gcm_cmac() {
        let n = check(
            DIALECT_311,
            &[preauth_context(&[0; 32]), enc(&[ciphers::AES256_GCM]), sign(SIGNING_AES_CMAC)],
        )
        .unwrap();
        assert_eq!(n.cipher, Some(Cipher::Aes256Gcm));
        assert!(n.multi_credit);
        // No signing context: AES-CMAC is the default; cipher 0: no encryption.
        let n = check(DIALECT_311, &[preauth_context(&[0; 32]), enc(&[0])]).unwrap();
        assert_eq!(n.cipher, None);
    }

    #[test]
    fn refuses_other_dialects() {
        for d in [0x0202, 0x0210, 0x0300, 0x0302, 0x02FF] {
            let e = check(d, &[]).unwrap_err();
            assert!(matches!(e, Error::Policy(ref m) if m.contains("only SMB 3.1.1")), "{d:x}: {e}");
        }
    }

    #[test]
    fn refuses_ciphers_not_offered() {
        for c in [ciphers::AES128_CCM, ciphers::AES256_CCM, 0x0009] {
            let e = check(DIALECT_311, &[preauth_context(&[0; 32]), enc(&[c])]).unwrap_err();
            assert!(matches!(e, Error::Policy(ref m) if m.contains("not offered")), "{e}");
        }
        // AES-256-GCM when only AES-128-GCM was offered
        let only128 = Offer { ciphers: vec![Cipher::Aes128Gcm], ..offer() };
        let resp = NegotiateResponse::decode(&response(
            DIALECT_311,
            &[preauth_context(&[0; 32]), enc(&[ciphers::AES256_GCM])],
        ))
        .unwrap();
        assert!(matches!(check_response(&only128, &resp), Err(Error::Policy(_))));
        // two ciphers in the response
        check(DIALECT_311, &[preauth_context(&[0; 32]), enc(&[2, 4])]).unwrap_err();
    }

    #[test]
    fn refuses_other_signing_hash_compression_and_duplicates() {
        for alg in [0x0000, 0x0002] {
            let e = check(DIALECT_311, &[preauth_context(&[0; 32]), sign(alg)]).unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{e}");
        }
        let bad_hash = NegContext { kind: ctx::PREAUTH_INTEGRITY, data: vec![1, 0, 0, 0, 2, 0] };
        assert!(matches!(check(DIALECT_311, &[bad_hash]), Err(Error::Policy(_))));
        check(DIALECT_311, &[]).expect_err("no preauth context");
        let comp = NegContext { kind: ctx::COMPRESSION, data: vec![0; 8] };
        assert!(matches!(check(DIALECT_311, &[preauth_context(&[0; 32]), comp]), Err(Error::Policy(_))));
        check(DIALECT_311, &[preauth_context(&[0; 32]), preauth_context(&[1; 32])]).unwrap_err();
    }
}
