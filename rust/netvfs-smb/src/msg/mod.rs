// SPDX-License-Identifier: LGPL-2.1-or-later
//! SMB2 message codecs (MS-SMB2 2.2). Pure functions over byte slices: no
//! I/O, no crypto.
//!
//! Offsets in SMB2 bodies count from the start of the SMB2 header, so every
//! decoder takes the whole message, header included. Every length and
//! offset from the wire is checked against the message before use, and
//! nothing is allocated from a wire length that was not checked against the
//! message or a cap.

pub mod file;
pub mod negotiate;
pub mod session;
pub mod tree;

use std::ops::Range;

use crate::error::{Result, protocol};
use crate::status::NtStatus;
use crate::wire::{Reader, Writer, from_u32};

/// Size of the SMB2 sync/async header.
pub const HEADER_LEN: usize = 64;
/// ProtocolId of a plain SMB2 message.
pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// ProtocolId of a compression transform (never negotiated, always refused).
pub const COMPRESSED_PROTOCOL_ID: [u8; 4] = [0xFC, b'S', b'M', b'B'];
/// MessageId of unsolicited notifications (OPLOCK_BREAK).
pub const NOTIFICATION_MID: u64 = u64::MAX;
/// Most elements accepted in one received compound chain (we send at most
/// four).
pub const MAX_CHAIN: usize = 16;

/// SMB2 commands (MS-SMB2 2.2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// NEGOTIATE.
    Negotiate,
    /// SESSION_SETUP.
    SessionSetup,
    /// LOGOFF.
    Logoff,
    /// TREE_CONNECT.
    TreeConnect,
    /// TREE_DISCONNECT.
    TreeDisconnect,
    /// CREATE.
    Create,
    /// CLOSE.
    Close,
    /// FLUSH.
    Flush,
    /// READ.
    Read,
    /// WRITE.
    Write,
    /// IOCTL.
    Ioctl,
    /// CANCEL.
    Cancel,
    /// ECHO.
    Echo,
    /// QUERY_DIRECTORY.
    QueryDirectory,
    /// QUERY_INFO.
    QueryInfo,
    /// SET_INFO.
    SetInfo,
    /// OPLOCK_BREAK (only ever received, and ignored).
    OplockBreak,
}

impl Command {
    /// Every command this client knows.
    pub const ALL: [Self; 17] = [
        Self::Negotiate,
        Self::SessionSetup,
        Self::Logoff,
        Self::TreeConnect,
        Self::TreeDisconnect,
        Self::Create,
        Self::Close,
        Self::Flush,
        Self::Read,
        Self::Write,
        Self::Ioctl,
        Self::Cancel,
        Self::Echo,
        Self::QueryDirectory,
        Self::QueryInfo,
        Self::SetInfo,
        Self::OplockBreak,
    ];

    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Negotiate => 0,
            Self::SessionSetup => 1,
            Self::Logoff => 2,
            Self::TreeConnect => 3,
            Self::TreeDisconnect => 4,
            Self::Create => 5,
            Self::Close => 6,
            Self::Flush => 7,
            Self::Read => 8,
            Self::Write => 9,
            Self::Ioctl => 11,
            Self::Cancel => 12,
            Self::Echo => 13,
            Self::QueryDirectory => 14,
            Self::QueryInfo => 16,
            Self::SetInfo => 17,
            Self::OplockBreak => 18,
        }
    }

    /// Name for messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Negotiate => "NEGOTIATE",
            Self::SessionSetup => "SESSION_SETUP",
            Self::Logoff => "LOGOFF",
            Self::TreeConnect => "TREE_CONNECT",
            Self::TreeDisconnect => "TREE_DISCONNECT",
            Self::Create => "CREATE",
            Self::Close => "CLOSE",
            Self::Flush => "FLUSH",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Ioctl => "IOCTL",
            Self::Cancel => "CANCEL",
            Self::Echo => "ECHO",
            Self::QueryDirectory => "QUERY_DIRECTORY",
            Self::QueryInfo => "QUERY_INFO",
            Self::SetInfo => "SET_INFO",
            Self::OplockBreak => "OPLOCK_BREAK",
        }
    }

    /// The command of a wire value.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }
}

/// The name of a command code, also for one this client does not know.
#[must_use]
pub fn command_name(code: u16) -> String {
    Command::from_code(code).map_or_else(|| format!("command {code}"), |c| c.name().to_owned())
}

/// SMB2 header flags (MS-SMB2 2.2.1.2).
pub mod flags {
    /// The message is a response.
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    /// Async header (interim and final async responses, CANCEL of them).
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    /// Compounded with the previous request, on its file.
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    /// The message is signed.
    pub const SIGNED: u32 = 0x0000_0008;
}

/// A decoded SMB2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// CreditCharge.
    pub credit_charge: u16,
    /// Status (responses); ChannelSequence/Reserved in requests is 0.
    pub status: NtStatus,
    /// Command code.
    pub command: u16,
    /// CreditRequest (requests) or CreditResponse (responses).
    pub credits: u16,
    /// Flags.
    pub flags: u32,
    /// NextCommand (compound chains).
    pub next_command: u32,
    /// MessageId.
    pub message_id: u64,
    /// AsyncId of an async header, else `None`.
    pub async_id: Option<u64>,
    /// TreeId of a sync header (0 in an async one).
    pub tree_id: u32,
    /// SessionId.
    pub session_id: u64,
    /// Signature.
    pub signature: [u8; 16],
}

impl Header {
    /// A sync request header with the given fields and everything else zero.
    #[must_use]
    pub fn request(command: Command, message_id: u64, session_id: u64, tree_id: u32) -> Self {
        Self {
            credit_charge: 0,
            status: NtStatus::SUCCESS,
            command: command.code(),
            credits: 0,
            flags: 0,
            next_command: 0,
            message_id,
            async_id: None,
            tree_id,
            session_id,
            signature: [0; 16],
        }
    }

    /// Appends the 64-byte header.
    pub fn encode(&self, w: &mut Writer) {
        w.bytes(&PROTOCOL_ID)
            .u16(64)
            .u16(self.credit_charge)
            .u32(self.status.0)
            .u16(self.command)
            .u16(self.credits)
            .u32(self.flags)
            .u32(self.next_command)
            .u64(self.message_id);
        match self.async_id {
            Some(id) => w.u64(id),
            None => w.u32(0).u32(self.tree_id),
        };
        w.u64(self.session_id).bytes(&self.signature);
    }

    /// Decodes the header at the start of `msg`.
    ///
    /// # Errors
    /// A wrong ProtocolId or StructureSize, or a short message.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let mut r = Reader::new(msg);
        if r.array::<4>()? != PROTOCOL_ID {
            return Err(protocol("not an SMB2 message"));
        }
        if r.u16()? != 64 {
            return Err(protocol("SMB2 header StructureSize is not 64"));
        }
        let credit_charge = r.u16()?;
        let status = NtStatus(r.u32()?);
        let command = r.u16()?;
        let credits = r.u16()?;
        let flags = r.u32()?;
        let next_command = r.u32()?;
        let message_id = r.u64()?;
        let (async_id, tree_id) = if flags & flags::ASYNC_COMMAND == 0 {
            r.skip(4)?;
            (None, r.u32()?)
        } else {
            (Some(r.u64()?), 0)
        };
        let session_id = r.u64()?;
        let signature = r.array()?;
        Ok(Self {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            async_id,
            tree_id,
            session_id,
            signature,
        })
    }

    /// The response flag is set.
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.flags & flags::SERVER_TO_REDIR != 0
    }

    /// The signed flag is set.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.flags & flags::SIGNED != 0
    }

    /// An interim response: STATUS_PENDING in an async header.
    #[must_use]
    pub fn is_interim(&self) -> bool {
        self.status == NtStatus::PENDING && self.async_id.is_some()
    }
}

/// A message: header and body.
#[must_use]
pub fn build(header: &Header, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    header.encode(&mut w);
    w.bytes(body);
    w.into_vec()
}

/// A reader at a response body whose StructureSize was checked.
///
/// # Errors
/// A short message or another StructureSize.
pub(crate) fn body_reader<'a>(msg: &'a [u8], structure_size: u16, what: &str) -> Result<Reader<'a>> {
    let mut r = Reader::new(msg);
    r.seek(HEADER_LEN)?;
    let got = r.u16()?;
    if got != structure_size {
        return Err(protocol(format!("{what}: StructureSize {got}, expected {structure_size}")));
    }
    Ok(r)
}

/// Checks an ERROR response body (MS-SMB2 2.2.2, StructureSize 9). Its data
/// is never used.
///
/// # Errors
/// A malformed error body.
pub fn check_error_response(msg: &[u8]) -> Result<()> {
    let mut r = body_reader(msg, 9, "ERROR")?;
    r.skip(2)?; // ErrorContextCount, Reserved
    let byte_count = from_u32(r.u32()?)?;
    if byte_count > r.remaining() {
        return Err(protocol("ERROR response ByteCount beyond the message"));
    }
    Ok(())
}

/// The elements of a received chain: each starts at the previous one's
/// NextCommand, which must leave room for a header, be 8-aligned and stay
/// inside the buffer. An element's range runs to the next element (its
/// padding included, as it was signed) or to the end.
///
/// # Errors
/// A malformed chain or more than [`MAX_CHAIN`] elements.
pub fn split_chain(buf: &[u8]) -> Result<Vec<Range<usize>>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    loop {
        if out.len() == MAX_CHAIN {
            return Err(protocol("compound response with too many elements"));
        }
        let element = buf.get(start..).ok_or_else(|| protocol("compound element outside the message"))?;
        let next = from_u32(Header::decode(element)?.next_command)?;
        if next == 0 {
            out.push(start..buf.len());
            return Ok(out);
        }
        if next < HEADER_LEN || !next.is_multiple_of(8) || next >= element.len() {
            return Err(protocol(format!("bad NextCommand {next} in a compound response")));
        }
        let end = start.checked_add(next).ok_or_else(|| protocol("NextCommand overflow"))?;
        out.push(start..end);
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(command: Command, mid: u64, next: u32, body: &[u8]) -> Vec<u8> {
        let mut h = Header::request(command, mid, 1, 1);
        h.flags = flags::SERVER_TO_REDIR;
        h.next_command = next;
        build(&h, body)
    }

    #[test]
    fn commands() {
        let codes: Vec<u16> = Command::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(codes, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18]);
        for c in Command::ALL {
            assert_eq!(Command::from_code(c.code()), Some(c));
            assert_eq!(command_name(c.code()), c.name());
        }
        assert_eq!(Command::from_code(10), None);
        assert_eq!(command_name(15), "command 15");
        let names: Vec<&str> = Command::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "NEGOTIATE",
                "SESSION_SETUP",
                "LOGOFF",
                "TREE_CONNECT",
                "TREE_DISCONNECT",
                "CREATE",
                "CLOSE",
                "FLUSH",
                "READ",
                "WRITE",
                "IOCTL",
                "CANCEL",
                "ECHO",
                "QUERY_DIRECTORY",
                "QUERY_INFO",
                "SET_INFO",
                "OPLOCK_BREAK"
            ]
        );
    }

    #[test]
    fn header_round_trip_sync_and_async() {
        let mut h = Header::request(Command::Read, 7, 0x1122_3344_5566_7788, 5);
        h.credit_charge = 16;
        h.credits = 32;
        h.flags = flags::SIGNED;
        h.next_command = 0x88;
        h.signature = [3; 16];
        let msg = build(&h, &[1, 2, 3]);
        assert_eq!(msg.len(), 67);
        assert_eq!(&msg[..8], &[0xFE, b'S', b'M', b'B', 64, 0, 16, 0]);
        assert_eq!(&msg[32..40], &[0, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(Header::decode(&msg).unwrap(), h);
        assert!(h.is_signed() && !h.is_response() && !h.is_interim());

        let mut a = h;
        a.flags = flags::ASYNC_COMMAND | flags::SERVER_TO_REDIR;
        a.async_id = Some(0xdead_beef);
        a.tree_id = 0;
        a.status = NtStatus::PENDING;
        let msg = build(&a, &[]);
        assert_eq!(&msg[32..40], &0xdead_beefu64.to_le_bytes());
        let d = Header::decode(&msg).unwrap();
        assert_eq!(d, a);
        assert!(d.is_response() && d.is_interim() && !d.is_signed());
        // PENDING in a sync header is not an interim response.
        let mut s = d;
        s.async_id = None;
        assert!(!s.is_interim());
    }

    #[test]
    fn header_rejects_garbage() {
        Header::decode(&[0; 63]).unwrap_err();
        let mut msg = build(&Header::request(Command::Echo, 1, 0, 0), &[]);
        Header::decode(&msg).unwrap();
        msg[0] = 0xFD;
        Header::decode(&msg).unwrap_err();
        msg[0] = 0xFE;
        msg[4] = 65;
        Header::decode(&msg).unwrap_err();
    }

    #[test]
    fn error_response_bounds() {
        let mut body = vec![9, 0, 0, 0, 0, 0, 0, 0, 0];
        check_error_response(&response(Command::Create, 1, 0, &body)).unwrap();
        body[4] = 1; // one byte of ErrorData: present
        check_error_response(&response(Command::Create, 1, 0, &body)).unwrap();
        body[4] = 2; // beyond the message
        check_error_response(&response(Command::Create, 1, 0, &body)).unwrap_err();
        check_error_response(&response(Command::Create, 1, 0, &[9, 0, 0, 0, 0, 0])).unwrap_err();
        check_error_response(&response(Command::Create, 1, 0, &[8, 0, 0, 0, 0, 0, 0, 0, 0])).unwrap_err();
    }

    #[test]
    fn chains_split_at_next_command() {
        let mut first = response(Command::Create, 1, 72, &[1, 2, 3, 4]);
        first.resize(72, 0);
        let second = response(Command::Close, 2, 0, &[9, 9]);
        let chain = [first.clone(), second].concat();
        assert_eq!(split_chain(&chain).unwrap(), [0..72, 72..138]);
        assert_eq!(split_chain(&second_only()).unwrap(), vec![0..66]);
        // NextCommand inside the header, unaligned, at or past the end.
        for next in [8u32, 70, 138, 4096] {
            let mut bad = chain.clone();
            bad[20..24].copy_from_slice(&next.to_le_bytes());
            split_chain(&bad).unwrap_err();
        }
        // NextCommand 64 is a header without a body: allowed.
        let mut bare = response(Command::Echo, 1, 64, &[]);
        bare.extend_from_slice(&response(Command::Echo, 2, 0, &[]));
        assert_eq!(split_chain(&bare).unwrap(), [0..64, 64..128]);
        // A chain of MAX_CHAIN + 1 elements.
        let element = response(Command::Echo, 1, 64, &[]);
        let mut long: Vec<u8> = element.repeat(MAX_CHAIN);
        long.extend_from_slice(&response(Command::Echo, 1, 0, &[]));
        split_chain(&long).unwrap_err();
        let mut max: Vec<u8> = element.repeat(MAX_CHAIN - 1);
        max.extend_from_slice(&response(Command::Echo, 1, 0, &[]));
        assert_eq!(split_chain(&max).unwrap().len(), MAX_CHAIN);
        split_chain(&[]).unwrap_err();
    }

    fn second_only() -> Vec<u8> {
        response(Command::Close, 2, 0, &[9, 9])
    }
}
