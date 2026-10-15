// SPDX-License-Identifier: LGPL-2.1-or-later
//! TREE_CONNECT (MS-SMB2 2.2.9, 2.2.10).

use super::{HEADER_LEN, body_reader};
use crate::error::Result;
use crate::names::utf16le;
use crate::wire::{Writer, to_u16};

/// Share flags of a TREE_CONNECT response.
pub mod share_flags {
    /// SMB2_SHAREFLAG_ENCRYPT_DATA.
    pub const ENCRYPT_DATA: u32 = 0x0000_8000;
}

/// Share types.
pub mod share_type {
    /// Disk.
    pub const DISK: u8 = 0x01;
    /// Named pipe.
    pub const PIPE: u8 = 0x02;
}

/// TREE_CONNECT request body for `\\server\share`, given as UTF-16.
///
/// # Errors
/// Path longer than a 16-bit length.
pub fn request(unc: &[u16]) -> Result<Vec<u8>> {
    let path = utf16le(unc);
    let mut w = Writer::new();
    w.u16(9).u16(0).u16(to_u16(HEADER_LEN.saturating_add(8))?).u16(to_u16(path.len())?).bytes(&path);
    Ok(w.into_vec())
}

/// TREE_CONNECT response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeConnectResponse {
    /// ShareType.
    pub share_type: u8,
    /// ShareFlags.
    pub share_flags: u32,
    /// Capabilities.
    pub capabilities: u32,
    /// MaximalAccess.
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    /// Decodes a TREE_CONNECT response message.
    ///
    /// # Errors
    /// Malformed body.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = body_reader(msg, 16, "TREE_CONNECT response")?;
        let share_type = r.u8()?;
        r.skip(1)?;
        Ok(Self { share_type, share_flags: r.u32()?, capabilities: r.u32()?, maximal_access: r.u32()? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Command, Header, build, flags};

    #[test]
    fn request_layout() {
        let unc: Vec<u16> = r"\\h\s".encode_utf16().collect();
        let b = request(&unc).unwrap();
        assert_eq!(&b[..8], &[9, 0, 0, 0, 72, 0, 10, 0]);
        assert_eq!(&b[8..], &[b'\\', 0, b'\\', 0, b'h', 0, b'\\', 0, b's', 0]);
    }

    #[test]
    fn response_decode() {
        let mut h = Header::request(Command::TreeConnect, 3, 1, 7);
        h.flags = flags::SERVER_TO_REDIR;
        let body = [16, 0, 1, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xff, 0x01, 0x1f, 0x00];
        let r = TreeConnectResponse::decode(&build(&h, &body)).unwrap();
        assert_eq!(r.share_type, share_type::DISK);
        assert_eq!(r.share_flags, share_flags::ENCRYPT_DATA);
        assert_eq!(r.maximal_access, 0x001f_01ff);
        TreeConnectResponse::decode(&build(&h, &body[..15])).unwrap_err();
    }
}
