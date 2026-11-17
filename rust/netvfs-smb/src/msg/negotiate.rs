// SPDX-License-Identifier: LGPL-2.1-or-later
//! NEGOTIATE request and response (MS-SMB2 2.2.3, 2.2.4) with negotiate
//! contexts (2.2.3.1).

use super::{HEADER_LEN, body_reader};
use crate::error::{Result, protocol};
use crate::wire::{Reader, Writer, from_u32, slice_at, to_u16, to_u32};

/// SMB 3.1.1.
pub const DIALECT_311: u16 = 0x0311;

/// Negotiate context types.
pub mod ctx {
    /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES.
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    /// SMB2_ENCRYPTION_CAPABILITIES.
    pub const ENCRYPTION: u16 = 0x0002;
    /// SMB2_COMPRESSION_CAPABILITIES.
    pub const COMPRESSION: u16 = 0x0003;
    /// SMB2_SIGNING_CAPABILITIES.
    pub const SIGNING: u16 = 0x0008;
}

/// Preauth hash algorithm SHA-512.
pub const HASH_SHA512: u16 = 0x0001;
/// Cipher ids.
pub mod ciphers {
    /// AES-128-CCM (never offered).
    pub const AES128_CCM: u16 = 0x0001;
    /// AES-128-GCM.
    pub const AES128_GCM: u16 = 0x0002;
    /// AES-256-CCM (never offered).
    pub const AES256_CCM: u16 = 0x0003;
    /// AES-256-GCM.
    pub const AES256_GCM: u16 = 0x0004;
}
/// Signing algorithm AES-CMAC.
pub const SIGNING_AES_CMAC: u16 = 0x0001;

/// Security mode bits.
pub mod security_mode {
    /// Signing enabled.
    pub const SIGNING_ENABLED: u16 = 0x0001;
    /// Signing required.
    pub const SIGNING_REQUIRED: u16 = 0x0002;
}

/// Global capability bits.
pub mod caps {
    /// Multi-credit operations.
    pub const LARGE_MTU: u32 = 0x0000_0004;
    /// Encryption (3.0/3.0.2 meaning; 3.1.1 uses the context).
    pub const ENCRYPTION: u32 = 0x0000_0040;
}

/// At most this many negotiate contexts are accepted in a response.
pub const MAX_CONTEXTS: usize = 16;
/// At most this many dialects are offered.
const MAX_DIALECTS: usize = 8;

/// One negotiate context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegContext {
    /// ContextType.
    pub kind: u16,
    /// Data.
    pub data: Vec<u8>,
}

/// NEGOTIATE request body.
#[derive(Debug, Clone)]
pub struct NegotiateRequest {
    /// SecurityMode.
    pub security_mode: u16,
    /// Capabilities.
    pub capabilities: u32,
    /// ClientGuid.
    pub client_guid: [u8; 16],
    /// Dialects.
    pub dialects: Vec<u16>,
    /// Negotiate contexts.
    pub contexts: Vec<NegContext>,
}

impl NegotiateRequest {
    /// Encodes the body (after the 64-byte header).
    ///
    /// # Errors
    /// Too many dialects/contexts or an oversized context.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.dialects.is_empty() || self.dialects.len() > MAX_DIALECTS {
            return Err(protocol("dialect count"));
        }
        let mut w = Writer::new();
        // Fixed part is 36 bytes; dialects follow; contexts start 8-aligned from the header.
        let dialects_end = HEADER_LEN
            .checked_add(36)
            .and_then(|v| v.checked_add(self.dialects.len().checked_mul(2)?))
            .ok_or_else(|| protocol("overflow"))?;
        let ctx_offset = dialects_end.checked_next_multiple_of(8).ok_or_else(|| protocol("overflow"))?;
        w.u16(36)
            .u16(to_u16(self.dialects.len())?)
            .u16(self.security_mode)
            .u16(0)
            .u32(self.capabilities)
            .bytes(&self.client_guid)
            .u32(to_u32(ctx_offset)?)
            .u16(to_u16(self.contexts.len())?)
            .u16(0);
        for d in &self.dialects {
            w.u16(*d);
        }
        for c in &self.contexts {
            // Each context starts 8-aligned relative to the header; the body starts at 64,
            // which is 8-aligned, so aligning the body is enough.
            w.align8();
            w.u16(c.kind).u16(to_u16(c.data.len())?).u32(0).bytes(&c.data);
        }
        Ok(w.into_vec())
    }
}

/// Builds the PREAUTH_INTEGRITY context: SHA-512 with a 32-byte salt.
#[must_use]
pub fn preauth_context(salt: &[u8; 32]) -> NegContext {
    let mut w = Writer::new();
    w.u16(1).u16(32).u16(HASH_SHA512).bytes(salt);
    NegContext { kind: ctx::PREAUTH_INTEGRITY, data: w.into_vec() }
}

/// Builds the ENCRYPTION context with the given cipher ids, in preference order.
///
/// # Errors
/// Too many ciphers.
pub fn encryption_context(ciphers: &[u16]) -> Result<NegContext> {
    let mut w = Writer::new();
    w.u16(to_u16(ciphers.len())?);
    for c in ciphers {
        w.u16(*c);
    }
    Ok(NegContext { kind: ctx::ENCRYPTION, data: w.into_vec() })
}

/// Builds the SIGNING context with AES-CMAC only.
#[must_use]
pub fn signing_context() -> NegContext {
    let mut w = Writer::new();
    w.u16(1).u16(SIGNING_AES_CMAC);
    NegContext { kind: ctx::SIGNING, data: w.into_vec() }
}

/// NEGOTIATE response body.
#[derive(Debug, Clone)]
pub struct NegotiateResponse {
    /// SecurityMode.
    pub security_mode: u16,
    /// DialectRevision.
    pub dialect: u16,
    /// ServerGuid.
    pub server_guid: [u8; 16],
    /// Capabilities.
    pub capabilities: u32,
    /// MaxTransactSize.
    pub max_transact: u32,
    /// MaxReadSize.
    pub max_read: u32,
    /// MaxWriteSize.
    pub max_write: u32,
    /// Length of the security buffer (GSS hint; unused).
    pub security_buffer_len: usize,
    /// Negotiate contexts (3.1.1 only).
    pub contexts: Vec<NegContext>,
}

impl NegotiateResponse {
    /// Decodes a NEGOTIATE response message (header included).
    ///
    /// # Errors
    /// Malformed body, offsets outside the message, too many contexts.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = body_reader(msg, 65, "NEGOTIATE response")?;
        let security_mode = r.u16()?;
        let dialect = r.u16()?;
        let context_count = usize::from(r.u16()?);
        let server_guid = r.array()?;
        let capabilities = r.u32()?;
        let max_transact = r.u32()?;
        let max_read = r.u32()?;
        let max_write = r.u32()?;
        let _system_time = r.u64()?;
        let _start_time = r.u64()?;
        let sec_offset = usize::from(r.u16()?);
        let sec_len = usize::from(r.u16()?);
        let ctx_offset = from_u32(r.u32()?)?;
        if sec_len > 0 {
            slice_at(msg, sec_offset, sec_len)?;
        }
        let mut contexts = Vec::new();
        if dialect == DIALECT_311 {
            if context_count > MAX_CONTEXTS {
                return Err(protocol(format!("{context_count} negotiate contexts")));
            }
            if !ctx_offset.is_multiple_of(8) {
                return Err(protocol("NegotiateContextOffset not 8-aligned"));
            }
            let mut cr = Reader::new(msg);
            cr.seek(ctx_offset)?;
            for _ in 0..context_count {
                // Each context starts 8-aligned (the first: checked above).
                let aligned = cr.pos().checked_next_multiple_of(8).ok_or_else(|| protocol("overflow"))?;
                cr.seek(aligned)?;
                let kind = cr.u16()?;
                let len = usize::from(cr.u16()?);
                cr.skip(4)?;
                let data = cr.bytes(len)?.to_vec();
                contexts.push(NegContext { kind, data });
            }
        }
        Ok(Self {
            security_mode,
            dialect,
            server_guid,
            capabilities,
            max_transact,
            max_read,
            max_write,
            security_buffer_len: sec_len,
            contexts,
        })
    }
}

/// A list of u16 values prefixed by a u16 count (cipher and signing contexts).
///
/// # Errors
/// Truncated data.
pub fn u16_list(data: &[u8]) -> Result<Vec<u16>> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u16()?);
    // The data length bounds the count before anything is allocated.
    if n > r.remaining() / 2 {
        return Err(protocol("list count beyond the context"));
    }
    (0..n).map(|_| r.u16()).collect()
}

/// PREAUTH_INTEGRITY context data: (hash algorithms, salt length).
///
/// # Errors
/// Truncated data.
pub fn parse_preauth(data: &[u8]) -> Result<(Vec<u16>, usize)> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u16()?);
    let salt_len = usize::from(r.u16()?);
    if n > r.remaining() / 2 {
        return Err(protocol("hash count beyond the context"));
    }
    let algs = (0..n).map(|_| r.u16()).collect::<Result<Vec<_>>>()?;
    r.skip(salt_len)?;
    Ok((algs, salt_len))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::msg::{Command, Header, build};

    fn request() -> NegotiateRequest {
        NegotiateRequest {
            security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
            capabilities: caps::LARGE_MTU,
            client_guid: [7; 16],
            dialects: vec![DIALECT_311],
            contexts: vec![
                preauth_context(&[1; 32]),
                encryption_context(&[ciphers::AES128_GCM, ciphers::AES256_GCM]).unwrap(),
                signing_context(),
            ],
        }
    }

    #[test]
    fn request_layout() {
        let body = request().encode().unwrap();
        assert_eq!(u32::from_le_bytes(body[28..32].try_into().unwrap()), 104);
        assert_eq!(u16::from_le_bytes(body[32..34].try_into().unwrap()), 3);
        assert_eq!(&body[36..38], &[0x11, 0x03]);
        assert_eq!(&body[40..44], &[1, 0, 38, 0]);
        assert_eq!(&body[88..92], &[2, 0, 6, 0]);
        assert_eq!(&body[96..102], &[2, 0, 2, 0, 4, 0]);
        assert_eq!(&body[104..112], &[8, 0, 4, 0, 0, 0, 0, 0]);
        NegotiateRequest { dialects: vec![], ..request() }.encode().unwrap_err();
        NegotiateRequest { dialects: vec![DIALECT_311; MAX_DIALECTS], ..request() }.encode().unwrap();
        NegotiateRequest { dialects: vec![DIALECT_311; MAX_DIALECTS + 1], ..request() }.encode().unwrap_err();
    }

    /// A response message like Samba's, built from the request contexts.
    pub(crate) fn response(dialect: u16, contexts: &[NegContext]) -> Vec<u8> {
        let mut w = Writer::new();
        let ctx_offset = 64 + 64 + 8;
        w.u16(65).u16(1).u16(dialect).u16(u16::try_from(contexts.len()).unwrap()).bytes(&[9; 16]);
        w.u32(caps::LARGE_MTU).u32(8 << 20).u32(8 << 20).u32(8 << 20).u64(0).u64(0);
        w.u16(128).u16(4).u32(ctx_offset);
        w.bytes(&[0x60, 0, 0, 0]).align8();
        for c in contexts {
            w.align8();
            w.u16(c.kind).u16(u16::try_from(c.data.len()).unwrap()).u32(0).bytes(&c.data);
        }
        let mut h = Header::request(Command::Negotiate, 0, 0, 0);
        h.flags = crate::msg::flags::SERVER_TO_REDIR;
        build(&h, &w.into_vec())
    }

    #[test]
    fn response_round_trip() {
        let ctxs = vec![
            preauth_context(&[2; 32]),
            encryption_context(&[ciphers::AES256_GCM]).unwrap(),
            signing_context(),
        ];
        let msg = response(DIALECT_311, &ctxs);
        let r = NegotiateResponse::decode(&msg).unwrap();
        assert_eq!(r.dialect, DIALECT_311);
        assert_eq!(r.contexts, ctxs);
        assert_eq!(u16_list(&r.contexts[1].data).unwrap(), vec![ciphers::AES256_GCM]);
        assert_eq!(parse_preauth(&r.contexts[0].data).unwrap(), (vec![HASH_SHA512], 32));
    }

    #[test]
    fn response_rejects_bad_offsets_and_counts() {
        let ctxs = vec![preauth_context(&[2; 32])];
        let mut msg = response(DIALECT_311, &ctxs);
        msg[64 + 6] = 200;
        NegotiateResponse::decode(&msg).unwrap_err();
        let mut msg = response(DIALECT_311, &ctxs);
        msg[64 + 60..64 + 64].copy_from_slice(&4000u32.to_le_bytes());
        NegotiateResponse::decode(&msg).unwrap_err();
        let mut msg = response(DIALECT_311, &ctxs);
        msg[64 + 60..64 + 64].copy_from_slice(&129u32.to_le_bytes());
        NegotiateResponse::decode(&msg).unwrap_err();
        let mut msg = response(DIALECT_311, &ctxs);
        let at = 64 + 64 + 8 + 2;
        msg[at..at + 2].copy_from_slice(&5000u16.to_le_bytes());
        NegotiateResponse::decode(&msg).unwrap_err();
        let mut msg = response(DIALECT_311, &ctxs);
        msg[64 + 56..64 + 58].copy_from_slice(&2000u16.to_le_bytes());
        NegotiateResponse::decode(&msg).unwrap_err();
        msg[64 + 58..64 + 60].copy_from_slice(&0u16.to_le_bytes());
        NegotiateResponse::decode(&msg).unwrap();
        let msg = response(DIALECT_311, &ctxs);
        NegotiateResponse::decode(&msg[..100]).unwrap_err();
        let max = vec![signing_context(); MAX_CONTEXTS];
        assert_eq!(NegotiateResponse::decode(&response(DIALECT_311, &max)).unwrap().contexts, max);
        let more = vec![signing_context(); MAX_CONTEXTS + 1];
        NegotiateResponse::decode(&response(DIALECT_311, &more)).unwrap_err();
    }

    #[test]
    fn list_counts_are_bounded_by_the_data() {
        u16_list(&[0xff, 0xff, 1, 0]).unwrap_err();
        assert_eq!(u16_list(&[2, 0, 1, 0]), Err(protocol("list count beyond the context")));
        assert_eq!(u16_list(&[1, 0, 1, 0, 9, 9]).unwrap(), [1]);
        parse_preauth(&[1, 0, 32, 0, 1, 0]).unwrap_err();
        parse_preauth(&[0xff, 0x7f, 0, 0]).unwrap_err();
        assert_eq!(parse_preauth(&[2, 0, 0, 0, 1, 0]), Err(protocol("hash count beyond the context")));
        assert_eq!(parse_preauth(&[1, 0, 1, 0, 1, 0, 7, 9]).unwrap(), (vec![1], 1));
    }
}
