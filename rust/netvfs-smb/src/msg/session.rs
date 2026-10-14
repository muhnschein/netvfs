// SPDX-License-Identifier: LGPL-2.1-or-later
//! SESSION_SETUP (MS-SMB2 2.2.5, 2.2.6), and the four-byte bodies of LOGOFF
//! (2.2.7, 2.2.8), TREE_DISCONNECT (2.2.11, 2.2.12), CANCEL (2.2.30) and
//! ECHO (2.2.28, 2.2.29).

use super::{HEADER_LEN, body_reader};
use crate::error::{Result, protocol};
use crate::wire::{Writer, slice_at, to_u16};

/// Session flags of a SESSION_SETUP response.
pub mod session_flags {
    /// SMB2_SESSION_FLAG_IS_GUEST.
    pub const IS_GUEST: u16 = 0x0001;
    /// SMB2_SESSION_FLAG_IS_NULL.
    pub const IS_NULL: u16 = 0x0002;
    /// SMB2_SESSION_FLAG_ENCRYPT_DATA.
    pub const ENCRYPT_DATA: u16 = 0x0004;
}

/// Largest security token accepted from the server (NTLM challenge and SPNEGO wrappers are
/// a few hundred bytes; Windows' Negotiate max token is 48 000).
pub const MAX_TOKEN: usize = 48_000;

/// SESSION_SETUP request body. Flags (binding) are always 0: no multichannel.
///
/// # Errors
/// Token longer than a 16-bit length.
pub fn setup_request(security_mode: u8, token: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(25)
        .u8(0) // Flags: no SMB2_SESSION_FLAG_BINDING
        .u8(security_mode)
        .u32(0) // Capabilities (DFS not claimed)
        .u32(0) // Channel
        .u16(to_u16(HEADER_LEN.saturating_add(24))?)
        .u16(to_u16(token.len())?)
        .u64(0) // PreviousSessionId
        .bytes(token);
    Ok(w.into_vec())
}

/// SESSION_SETUP response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupResponse {
    /// SessionFlags.
    pub session_flags: u16,
    /// Security token (may be empty).
    pub token: Vec<u8>,
}

impl SetupResponse {
    /// Decodes a SESSION_SETUP response message.
    ///
    /// # Errors
    /// Malformed body, token outside the message or above [`MAX_TOKEN`].
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = body_reader(msg, 9, "SESSION_SETUP response")?;
        let session_flags = r.u16()?;
        let offset = usize::from(r.u16()?);
        let len = usize::from(r.u16()?);
        if len > MAX_TOKEN {
            return Err(protocol("security token too long"));
        }
        let token = if len == 0 { Vec::new() } else { slice_at(msg, offset, len)?.to_vec() };
        Ok(Self { session_flags, token })
    }
}

/// The request body of LOGOFF, TREE_DISCONNECT, CANCEL and ECHO
/// (StructureSize 4, Reserved).
#[must_use]
pub fn four_byte_request() -> Vec<u8> {
    vec![4, 0, 0, 0]
}

/// Checks a LOGOFF, TREE_DISCONNECT or ECHO response body (StructureSize
/// 4).
///
/// # Errors
/// Wrong StructureSize.
pub fn check_four_byte_response(msg: &[u8], what: &str) -> Result<()> {
    body_reader(msg, 4, what).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Command, Header, build, flags};

    fn resp(body: &[u8]) -> Vec<u8> {
        let mut h = Header::request(Command::SessionSetup, 1, 5, 0);
        h.flags = flags::SERVER_TO_REDIR;
        build(&h, body)
    }

    #[test]
    fn request_layout() {
        let b = setup_request(2, b"TOKEN").unwrap();
        assert_eq!(b.len(), 24 + 5);
        assert_eq!(&b[..4], &[25, 0, 0, 2]);
        assert_eq!(u16::from_le_bytes([b[12], b[13]]), 88);
        assert_eq!(u16::from_le_bytes([b[14], b[15]]), 5);
        assert_eq!(&b[24..], b"TOKEN");
    }

    #[test]
    fn response_decode_and_bounds() {
        let ok = resp(&[9, 0, 4, 0, 72, 0, 3, 0, b'a', b'b', b'c']);
        assert_eq!(
            SetupResponse::decode(&ok).unwrap(),
            SetupResponse { session_flags: session_flags::ENCRYPT_DATA, token: b"abc".to_vec() }
        );
        let empty = resp(&[9, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(SetupResponse::decode(&empty).unwrap().token.is_empty());
        // token runs past the end
        SetupResponse::decode(&resp(&[9, 0, 0, 0, 72, 0, 9, 0, 1])).unwrap_err();
        // token above the cap
        SetupResponse::decode(&resp(&[9, 0, 0, 0, 72, 0, 0xff, 0xff])).unwrap_err();
        // wrong structure size
        SetupResponse::decode(&resp(&[8, 0, 0, 0, 0, 0, 0, 0])).unwrap_err();
    }

    #[test]
    fn four_byte_messages() {
        assert_eq!(four_byte_request(), vec![4, 0, 0, 0]);
        check_four_byte_response(&resp(&[4, 0, 0, 0]), "LOGOFF").unwrap();
        check_four_byte_response(&resp(&[5, 0, 0, 0]), "LOGOFF").unwrap_err();
    }
}
