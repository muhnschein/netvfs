// SPDX-License-Identifier: LGPL-2.1-or-later
//! SFTP version 3 (draft-ietf-secsh-filexfer-02) and the OpenSSH
//! extensions this backend uses: message types, status codes, open flags,
//! [`Attrs`], the server's replies ([`Reply`]) and `VERSION`
//! ([`ServerVersion`]). Decoders check every count and length against the
//! caps of design §3.2 before anything is allocated.

use crate::wire::{Packet, Reader, WireError};

/// `SSH_FXP_INIT`.
pub const FXP_INIT: u8 = 1;
/// `SSH_FXP_VERSION`.
pub const FXP_VERSION: u8 = 2;
/// `SSH_FXP_OPEN`.
pub const FXP_OPEN: u8 = 3;
/// `SSH_FXP_CLOSE`.
pub const FXP_CLOSE: u8 = 4;
/// `SSH_FXP_READ`.
pub const FXP_READ: u8 = 5;
/// `SSH_FXP_WRITE`.
pub const FXP_WRITE: u8 = 6;
/// `SSH_FXP_LSTAT`.
pub const FXP_LSTAT: u8 = 7;
/// `SSH_FXP_FSTAT`.
pub const FXP_FSTAT: u8 = 8;
/// `SSH_FXP_SETSTAT`.
pub const FXP_SETSTAT: u8 = 9;
/// `SSH_FXP_OPENDIR`.
pub const FXP_OPENDIR: u8 = 11;
/// `SSH_FXP_READDIR`.
pub const FXP_READDIR: u8 = 12;
/// `SSH_FXP_REMOVE`.
pub const FXP_REMOVE: u8 = 13;
/// `SSH_FXP_MKDIR`.
pub const FXP_MKDIR: u8 = 14;
/// `SSH_FXP_RMDIR`.
pub const FXP_RMDIR: u8 = 15;
/// `SSH_FXP_REALPATH`.
pub const FXP_REALPATH: u8 = 16;
/// `SSH_FXP_STAT`.
pub const FXP_STAT: u8 = 17;
/// `SSH_FXP_RENAME`.
pub const FXP_RENAME: u8 = 18;
/// `SSH_FXP_READLINK`.
pub const FXP_READLINK: u8 = 19;
/// `SSH_FXP_SYMLINK`.
pub const FXP_SYMLINK: u8 = 20;
/// `SSH_FXP_STATUS`.
pub const FXP_STATUS: u8 = 101;
/// `SSH_FXP_HANDLE`.
pub const FXP_HANDLE: u8 = 102;
/// `SSH_FXP_DATA`.
pub const FXP_DATA: u8 = 103;
/// `SSH_FXP_NAME`.
pub const FXP_NAME: u8 = 104;
/// `SSH_FXP_ATTRS`.
pub const FXP_ATTRS: u8 = 105;
/// `SSH_FXP_EXTENDED`.
pub const FXP_EXTENDED: u8 = 200;
/// `SSH_FXP_EXTENDED_REPLY`.
pub const FXP_EXTENDED_REPLY: u8 = 201;

/// The protocol version this client speaks.
pub const VERSION: u32 = 3;

/// `SSH_FX_OK`.
pub const FX_OK: u32 = 0;
/// `SSH_FX_EOF`.
pub const FX_EOF: u32 = 1;
/// `SSH_FX_NO_SUCH_FILE`.
pub const FX_NO_SUCH_FILE: u32 = 2;
/// `SSH_FX_PERMISSION_DENIED`.
pub const FX_PERMISSION_DENIED: u32 = 3;
/// `SSH_FX_FAILURE`.
pub const FX_FAILURE: u32 = 4;
/// `SSH_FX_BAD_MESSAGE`.
pub const FX_BAD_MESSAGE: u32 = 5;
/// `SSH_FX_NO_CONNECTION`.
pub const FX_NO_CONNECTION: u32 = 6;
/// `SSH_FX_CONNECTION_LOST`.
pub const FX_CONNECTION_LOST: u32 = 7;
/// `SSH_FX_OP_UNSUPPORTED`.
pub const FX_OP_UNSUPPORTED: u32 = 8;
/// `SSH_FX_NO_SUCH_PATH` (later drafts; some v3 servers send it).
pub const FX_NO_SUCH_PATH: u32 = 10;
/// `SSH_FX_FILE_ALREADY_EXISTS` (later drafts).
pub const FX_FILE_ALREADY_EXISTS: u32 = 11;
/// `SSH_FX_WRITE_PROTECT` (later drafts).
pub const FX_WRITE_PROTECT: u32 = 12;

/// `SSH_FXF_READ`.
pub const FXF_READ: u32 = 0x01;
/// `SSH_FXF_WRITE`.
pub const FXF_WRITE: u32 = 0x02;
/// `SSH_FXF_CREAT`.
pub const FXF_CREAT: u32 = 0x08;
/// `SSH_FXF_TRUNC`.
pub const FXF_TRUNC: u32 = 0x10;
/// `SSH_FXF_EXCL`.
pub const FXF_EXCL: u32 = 0x20;

const ATTR_SIZE: u32 = 0x01;
const ATTR_UIDGID: u32 = 0x02;
const ATTR_PERMISSIONS: u32 = 0x04;
const ATTR_ACMODTIME: u32 = 0x08;
const ATTR_EXTENDED: u32 = 0x8000_0000;

/// Longest file name or path accepted from the server.
pub const MAX_NAME: usize = 4096;
/// Most `extended` pairs in one attribute block.
pub const MAX_ATTR_EXTENSIONS: u32 = 64;
/// Most names in one `NAME` reply.
pub const MAX_NAMES: u32 = 4096;
/// Longest handle accepted (the draft allows 256 bytes).
pub const MAX_HANDLE: usize = 256;
/// Most extensions in `VERSION`.
pub const MAX_EXTENSIONS: usize = 64;
/// Longest extension name or data in `VERSION`.
pub const MAX_EXTENSION_FIELD: usize = 4096;
/// The part of a status message that is kept.
pub const MAX_MESSAGE: usize = 1024;

/// File attributes (draft-02 §5); `None` where the flag is not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs {
    /// Size in bytes.
    pub size: Option<u64>,
    /// Owner and group ids.
    pub ids: Option<(u32, u32)>,
    /// `st_mode`: type and permission bits.
    pub permissions: Option<u32>,
    /// Access and modification time, seconds since the epoch.
    pub times: Option<(u32, u32)>,
}

impl Attrs {
    /// Reads an attribute block; extended pairs are skipped, at most
    /// [`MAX_ATTR_EXTENSIONS`] of them. Unknown flag bits carry no fields
    /// in v3 and are ignored.
    ///
    /// # Errors
    /// A short block or too many extended pairs.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let flags = r.u32()?;
        let mut attrs = Self::default();
        if flags & ATTR_SIZE != 0 {
            attrs.size = Some(r.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            attrs.ids = Some((r.u32()?, r.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(r.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            attrs.times = Some((r.u32()?, r.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            let count = r.u32()?;
            if count > MAX_ATTR_EXTENSIONS {
                return Err(WireError("too many extended attributes"));
            }
            for _ in 0..count {
                r.skip_string()?;
                r.skip_string()?;
            }
        }
        Ok(attrs)
    }

    /// Appends the block to `p` (never with extended pairs).
    #[must_use]
    pub fn encode(&self, p: Packet) -> Packet {
        let mut flags = 0;
        for (set, bit) in [
            (self.size.is_some(), ATTR_SIZE),
            (self.ids.is_some(), ATTR_UIDGID),
            (self.permissions.is_some(), ATTR_PERMISSIONS),
            (self.times.is_some(), ATTR_ACMODTIME),
        ] {
            if set {
                flags |= bit;
            }
        }
        let mut p = p.u32(flags);
        if let Some(size) = self.size {
            p = p.u64(size);
        }
        if let Some((uid, gid)) = self.ids {
            p = p.u32(uid).u32(gid);
        }
        if let Some(permissions) = self.permissions {
            p = p.u32(permissions);
        }
        if let Some((atime, mtime)) = self.times {
            p = p.u32(atime).u32(mtime);
        }
        p
    }
}

/// One entry of a `NAME` reply; the `longname` is skipped (it is text for
/// people, not parsed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// The file name, or the path of `REALPATH` and `READLINK`.
    pub filename: Vec<u8>,
    /// Its attributes (often empty for `REALPATH` and `READLINK`).
    pub attrs: Attrs,
}

/// `SSH_FXP_STATUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
    /// The `SSH_FX_*` code.
    pub code: u32,
    /// The server's message, at most [`MAX_MESSAGE`] bytes of it, as text.
    pub message: String,
}

/// A reply to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `SSH_FXP_STATUS`.
    Status(StatusReply),
    /// `SSH_FXP_HANDLE`.
    Handle(Vec<u8>),
    /// `SSH_FXP_DATA`.
    Data(Vec<u8>),
    /// `SSH_FXP_NAME`.
    Name(Vec<Name>),
    /// `SSH_FXP_ATTRS`.
    Attrs(Attrs),
    /// `SSH_FXP_EXTENDED_REPLY`: the extension's own data.
    Extended(Vec<u8>),
}

/// Reads a reply: its request id and the reply.
///
/// # Errors
/// An unknown type, a field over its cap, a short packet or bytes left over.
pub fn decode_reply(body: &[u8]) -> Result<(u32, Reply), WireError> {
    let mut r = Reader::new(body);
    let kind = r.u8()?;
    let id = r.u32()?;
    let reply = match kind {
        FXP_STATUS => {
            let code = r.u32()?;
            // Old servers end the packet after the code.
            let (message, _language) = if r.is_empty() {
                (&b""[..], &b""[..])
            } else {
                (r.string(crate::wire::MAX_PACKET, "")?, r.string(crate::wire::MAX_PACKET, "")?)
            };
            let kept = message.get(..MAX_MESSAGE).unwrap_or(message);
            Reply::Status(StatusReply { code, message: String::from_utf8_lossy(kept).into_owned() })
        }
        FXP_HANDLE => Reply::Handle(r.string(MAX_HANDLE, "the handle is too long")?.to_vec()),
        FXP_DATA => Reply::Data(r.string(crate::wire::MAX_PACKET, "")?.to_vec()),
        FXP_NAME => {
            let count = r.u32()?;
            if count > MAX_NAMES {
                return Err(WireError("too many names in one reply"));
            }
            let mut names = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
            for _ in 0..count {
                let filename = r.string(MAX_NAME, "a name is too long")?.to_vec();
                r.skip_string()?;
                let attrs = Attrs::decode(&mut r)?;
                names.push(Name { filename, attrs });
            }
            Reply::Name(names)
        }
        FXP_ATTRS => Reply::Attrs(Attrs::decode(&mut r)?),
        FXP_EXTENDED_REPLY => Reply::Extended(r.rest().to_vec()),
        _ => return Err(WireError("a reply of an unknown type")),
    };
    if r.is_empty() { Ok((id, reply)) } else { Err(WireError("a reply has bytes left over")) }
}

/// One extension of `VERSION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// `posix-rename@openssh.com`, …
    pub name: Vec<u8>,
    /// Usually its version as text (`1`).
    pub data: Vec<u8>,
}

/// `SSH_FXP_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVersion {
    /// The version the server speaks.
    pub version: u32,
    /// Its extensions, in its order.
    pub extensions: Vec<Extension>,
}

impl ServerVersion {
    /// Whether `name` is offered with exactly `data`.
    #[must_use]
    pub fn offers(&self, name: &str, data: &str) -> bool {
        self.extensions.iter().any(|e| e.name == name.as_bytes() && e.data == data.as_bytes())
    }
}

/// Reads `VERSION`.
///
/// # Errors
/// Another type, more than [`MAX_EXTENSIONS`] extensions, a field over
/// [`MAX_EXTENSION_FIELD`], a short packet.
pub fn decode_version(body: &[u8]) -> Result<ServerVersion, WireError> {
    let mut r = Reader::new(body);
    if r.u8()? != FXP_VERSION {
        return Err(WireError("the server did not answer with VERSION"));
    }
    let version = r.u32()?;
    let mut extensions = Vec::new();
    while !r.is_empty() {
        if extensions.len() >= MAX_EXTENSIONS {
            return Err(WireError("too many extensions"));
        }
        let name = r.string(MAX_EXTENSION_FIELD, "an extension name is too long")?.to_vec();
        let data = r.string(MAX_EXTENSION_FIELD, "an extension is too long")?.to_vec();
        extensions.push(Extension { name, data });
    }
    Ok(ServerVersion { version, extensions })
}

/// The reply of `statvfs@openssh.com` (struct statvfs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Statvfs {
    /// `f_bsize`.
    pub bsize: u64,
    /// `f_frsize`.
    pub frsize: u64,
    /// `f_blocks`.
    pub blocks: u64,
    /// `f_bfree`.
    pub bfree: u64,
    /// `f_bavail`.
    pub bavail: u64,
}

impl Statvfs {
    /// Reads the eleven `uint64` of the reply; the last six are not used.
    ///
    /// # Errors
    /// A short or long reply.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(data);
        let s =
            Self { bsize: r.u64()?, frsize: r.u64()?, blocks: r.u64()?, bfree: r.u64()?, bavail: r.u64()? };
        for _ in 0..6 {
            r.u64()?;
        }
        if r.is_empty() { Ok(s) } else { Err(WireError("a statvfs reply has bytes left over")) }
    }
}

/// The reply of `limits@openssh.com`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// Longest packet.
    pub max_packet: u64,
    /// Longest READ answer.
    pub max_read: u64,
    /// Longest WRITE.
    pub max_write: u64,
    /// Most open handles (0: no limit).
    pub max_open_handles: u64,
}

impl Limits {
    /// Reads the four `uint64`.
    ///
    /// # Errors
    /// A short or long reply.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(data);
        let l = Self {
            max_packet: r.u64()?,
            max_read: r.u64()?,
            max_write: r.u64()?,
            max_open_handles: r.u64()?,
        };
        if r.is_empty() { Ok(l) } else { Err(WireError("a limits reply has bytes left over")) }
    }
}

/// Longest user or group name kept.
pub const MAX_OWNER_NAME: usize = 256;

/// User names and group names, each in the order of the ids asked for.
pub type OwnerNames = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Reads the reply of `users-groups-by-id@openssh.com`: one name per id
/// asked for (empty when unknown), users then groups.
///
/// # Errors
/// Another number of names than ids, a name over [`MAX_OWNER_NAME`], a short
/// reply.
pub fn decode_owner_names(data: &[u8], users: usize, groups: usize) -> Result<OwnerNames, WireError> {
    fn names(blob: &[u8], count: usize) -> Result<Vec<Vec<u8>>, WireError> {
        let mut r = Reader::new(blob);
        let mut out = Vec::with_capacity(count);
        while !r.is_empty() {
            if out.len() >= count {
                return Err(WireError("more names than ids"));
            }
            out.push(r.string(MAX_OWNER_NAME, "an owner name is too long")?.to_vec());
        }
        if out.len() == count { Ok(out) } else { Err(WireError("fewer names than ids")) }
    }
    let mut r = Reader::new(data);
    let user_blob = r.string(crate::wire::MAX_PACKET, "")?;
    let group_blob = r.string(crate::wire::MAX_PACKET, "")?;
    if !r.is_empty() {
        return Err(WireError("an owner reply has bytes left over"));
    }
    Ok((names(user_blob, users)?, names(group_blob, groups)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(v.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    fn body(kind: u8, id: u32, rest: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&id.to_be_bytes());
        for part in rest {
            out.extend_from_slice(part);
        }
        out
    }

    fn be(v: u32) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    fn be64(v: u64) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    #[test]
    fn attrs_round_trip_every_field() {
        let all = Attrs {
            size: Some(1 << 40),
            ids: Some((1000, 100)),
            permissions: Some(0o100_644),
            times: Some((5, 6)),
        };
        for attrs in [Attrs::default(), all, Attrs { permissions: Some(0o755), ..Attrs::default() }] {
            let bytes = attrs.encode(Packet::request(9)).finish(0).unwrap();
            let mut r = Reader::new(&bytes[9..]);
            assert_eq!(Attrs::decode(&mut r), Ok(attrs));
            assert!(r.is_empty());
        }
        let bytes = all.encode(Packet::request(9)).finish(0).unwrap();
        assert_eq!(&bytes[9..13], &[0, 0, 0, 0x0f]);
        let times =
            Attrs { times: Some((1, 2)), ..Attrs::default() }.encode(Packet::request(9)).finish(0).unwrap();
        assert_eq!(&times[9..], &[0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 2]);
        let ids =
            Attrs { ids: Some((3, 4)), ..Attrs::default() }.encode(Packet::request(9)).finish(0).unwrap();
        assert_eq!(&ids[9..], &[0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]);
        let size = Attrs { size: Some(7), ..Attrs::default() }.encode(Packet::request(9)).finish(0).unwrap();
        assert_eq!(&size[9..], &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7]);
    }

    #[test]
    fn attrs_skip_extensions_and_ignore_unknown_bits() {
        let mut b = be(0x8000_0000 | 0x40 | ATTR_PERMISSIONS);
        b.extend(be(0o40755));
        b.extend(be(2));
        for part in [&b"a@x"[..], b"1", b"b@x", b"22"] {
            b.extend(s(part));
        }
        let mut r = Reader::new(&b);
        assert_eq!(Attrs::decode(&mut r), Ok(Attrs { permissions: Some(0o40755), ..Attrs::default() }));
        assert!(r.is_empty());
    }

    #[test]
    fn attrs_refuse_too_many_extensions_and_short_blocks() {
        let mut b = be(ATTR_EXTENDED);
        b.extend(be(65));
        assert_eq!(Attrs::decode(&mut Reader::new(&b)), Err(WireError("too many extended attributes")));
        // 64 is the cap: accepted when they are there.
        let mut b = be(ATTR_EXTENDED);
        b.extend(be(64));
        for _ in 0..128 {
            b.extend(s(b""));
        }
        assert_eq!(Attrs::decode(&mut Reader::new(&b)), Ok(Attrs::default()));
        for flags in [ATTR_SIZE, ATTR_UIDGID, ATTR_PERMISSIONS, ATTR_ACMODTIME, ATTR_EXTENDED] {
            assert_eq!(
                Attrs::decode(&mut Reader::new(&be(flags))),
                Err(WireError("the packet ends early")),
                "{flags:#x}"
            );
        }
    }

    #[test]
    fn status_replies_keep_a_bounded_message() {
        let r = decode_reply(&body(FXP_STATUS, 7, &[&be(4), &s(b"Failure"), &s(b"en")])).unwrap();
        assert_eq!(r, (7, Reply::Status(StatusReply { code: 4, message: "Failure".into() })));
        // Old servers send only the code.
        let r = decode_reply(&body(FXP_STATUS, 1, &[&be(2)])).unwrap();
        assert_eq!(r.1, Reply::Status(StatusReply { code: 2, message: String::new() }));
        let long = vec![b'x'; MAX_MESSAGE + 10];
        let Reply::Status(st) = decode_reply(&body(FXP_STATUS, 1, &[&be(4), &s(&long), &s(b"")])).unwrap().1
        else {
            panic!("not a status");
        };
        assert_eq!(st.message.len(), MAX_MESSAGE);
        let invalid = decode_reply(&body(FXP_STATUS, 1, &[&be(4), &s(b"a\xffb"), &s(b"")])).unwrap().1;
        assert_eq!(invalid, Reply::Status(StatusReply { code: 4, message: "a\u{fffd}b".into() }));
        // A message without its language tag is short.
        decode_reply(&body(FXP_STATUS, 1, &[&be(4), &s(b"m")])).unwrap_err();
    }

    #[test]
    fn handles_are_capped() {
        let ok = vec![1; MAX_HANDLE];
        assert_eq!(decode_reply(&body(FXP_HANDLE, 2, &[&s(&ok)])), Ok((2, Reply::Handle(ok.clone()))));
        let long = vec![1; MAX_HANDLE + 1];
        assert_eq!(
            decode_reply(&body(FXP_HANDLE, 2, &[&s(&long)])),
            Err(WireError("the handle is too long"))
        );
    }

    #[test]
    fn data_and_attrs_and_extended() {
        assert_eq!(decode_reply(&body(FXP_DATA, 3, &[&s(b"abc")])), Ok((3, Reply::Data(b"abc".to_vec()))));
        let attrs = decode_reply(&body(FXP_ATTRS, 4, &[&be(ATTR_SIZE), &be64(9)])).unwrap();
        assert_eq!(attrs.1, Reply::Attrs(Attrs { size: Some(9), ..Attrs::default() }));
        let ext = decode_reply(&body(FXP_EXTENDED_REPLY, 5, &[b"\x01\x02"])).unwrap();
        assert_eq!(ext, (5, Reply::Extended(vec![1, 2])));
        assert_eq!(decode_reply(&body(FXP_EXTENDED_REPLY, 5, &[])).unwrap().1, Reply::Extended(vec![]));
    }

    #[test]
    fn names_are_read_and_capped() {
        let one = [s(b"file"), s(b"-rw-r--r-- 1 a b 3 Jan 1 file"), be(ATTR_SIZE), be64(3)].concat();
        let two = [s(b"x\xff"), s(b""), be(0)].concat();
        let r = decode_reply(&body(FXP_NAME, 6, &[&be(2), &one, &two])).unwrap();
        assert_eq!(
            r.1,
            Reply::Name(vec![
                Name { filename: b"file".to_vec(), attrs: Attrs { size: Some(3), ..Attrs::default() } },
                Name { filename: b"x\xff".to_vec(), attrs: Attrs::default() },
            ])
        );
        // Count over the cap: refused before reading any name.
        assert_eq!(
            decode_reply(&body(FXP_NAME, 6, &[&be(MAX_NAMES + 1)])),
            Err(WireError("too many names in one reply"))
        );
        // A count larger than what follows is a short packet, not an allocation.
        let short = decode_reply(&body(FXP_NAME, 6, &[&be(MAX_NAMES)])).unwrap_err();
        assert_ne!(short, WireError("too many names in one reply"));
        // At the cap: read.
        let full: Vec<u8> = (0..MAX_NAMES).flat_map(|_| two.clone()).collect();
        let r = decode_reply(&body(FXP_NAME, 6, &[&be(MAX_NAMES), &full])).unwrap();
        assert!(matches!(r.1, Reply::Name(n) if n.len() == usize::try_from(MAX_NAMES).unwrap()));
        let long = vec![b'a'; MAX_NAME + 1];
        let entry = [s(&long), s(b""), be(0)].concat();
        assert_eq!(decode_reply(&body(FXP_NAME, 6, &[&be(1), &entry])), Err(WireError("a name is too long")));
        let at_cap = [s(&long[1..]), s(b""), be(0)].concat();
        decode_reply(&body(FXP_NAME, 6, &[&be(1), &at_cap])).unwrap();
    }

    #[test]
    fn replies_refuse_unknown_types_and_trailing_bytes() {
        assert_eq!(decode_reply(&body(99, 1, &[])), Err(WireError("a reply of an unknown type")));
        assert_eq!(decode_reply(&body(FXP_VERSION, 1, &[])), Err(WireError("a reply of an unknown type")));
        assert_eq!(
            decode_reply(&body(FXP_HANDLE, 1, &[&s(b"h"), b"!"])),
            Err(WireError("a reply has bytes left over"))
        );
        decode_reply(&[FXP_STATUS, 0, 0]).unwrap_err();
        decode_reply(&[]).unwrap_err();
    }

    #[test]
    fn version_lists_extensions_with_caps() {
        let mut b = vec![FXP_VERSION];
        b.extend(be(3));
        for (n, d) in [(&b"posix-rename@openssh.com"[..], &b"1"[..]), (b"statvfs@openssh.com", b"2")] {
            b.extend(s(n));
            b.extend(s(d));
        }
        let v = decode_version(&b).unwrap();
        assert_eq!(v.version, 3);
        assert_eq!(v.extensions.len(), 2);
        assert!(v.offers("posix-rename@openssh.com", "1"));
        assert!(v.offers("statvfs@openssh.com", "2"));
        assert!(!v.offers("statvfs@openssh.com", "1"));
        assert!(!v.offers("fsync@openssh.com", "1"));

        let mut many = vec![FXP_VERSION, 0, 0, 0, 3];
        for _ in 0..MAX_EXTENSIONS {
            many.extend(s(b"e"));
            many.extend(s(b"1"));
        }
        assert_eq!(decode_version(&many).unwrap().extensions.len(), MAX_EXTENSIONS);
        many.extend(s(b"e"));
        many.extend(s(b"1"));
        assert_eq!(decode_version(&many), Err(WireError("too many extensions")));

        let long = vec![b'n'; MAX_EXTENSION_FIELD + 1];
        let b = [vec![FXP_VERSION, 0, 0, 0, 3], s(&long), s(b"1")].concat();
        assert_eq!(decode_version(&b), Err(WireError("an extension name is too long")));
        let b = [vec![FXP_VERSION, 0, 0, 0, 3], s(b"n"), s(&long)].concat();
        assert_eq!(decode_version(&b), Err(WireError("an extension is too long")));
        assert_eq!(
            decode_version(&[FXP_STATUS, 0, 0, 0, 3]),
            Err(WireError("the server did not answer with VERSION"))
        );
        decode_version(&[FXP_VERSION, 0, 0]).unwrap_err();
        // A name without its data.
        decode_version(&[vec![FXP_VERSION, 0, 0, 0, 3], s(b"n")].concat()).unwrap_err();
    }

    #[test]
    fn statvfs_and_limits() {
        let v: Vec<u8> = (1..=11u64).flat_map(u64::to_be_bytes).collect();
        assert_eq!(Statvfs::decode(&v), Ok(Statvfs { bsize: 1, frsize: 2, blocks: 3, bfree: 4, bavail: 5 }));
        Statvfs::decode(&v[..80]).unwrap_err();
        Statvfs::decode(&[v, vec![0]].concat()).unwrap_err();
        let l: Vec<u8> = (1..=4u64).flat_map(u64::to_be_bytes).collect();
        assert_eq!(
            Limits::decode(&l),
            Ok(Limits { max_packet: 1, max_read: 2, max_write: 3, max_open_handles: 4 })
        );
        Limits::decode(&l[..31]).unwrap_err();
        Limits::decode(&[l, vec![0]].concat()).unwrap_err();
    }

    #[test]
    fn owner_names_match_the_ids() {
        let users = [s(b"alice"), s(b"")].concat();
        let groups = s(b"staff");
        let reply = [s(&users), s(&groups)].concat();
        assert_eq!(
            decode_owner_names(&reply, 2, 1),
            Ok((vec![b"alice".to_vec(), Vec::new()], vec![b"staff".to_vec()]))
        );
        assert_eq!(decode_owner_names(&reply, 1, 1), Err(WireError("more names than ids")));
        assert_eq!(decode_owner_names(&reply, 3, 1), Err(WireError("fewer names than ids")));
        assert_eq!(decode_owner_names(&[s(b""), s(b"")].concat(), 0, 0), Ok((vec![], vec![])));
        let long = s(&[b'u'; MAX_OWNER_NAME + 1]);
        assert_eq!(
            decode_owner_names(&[s(&long), s(b"")].concat(), 1, 0),
            Err(WireError("an owner name is too long"))
        );
        assert_eq!(
            decode_owner_names(&[s(b""), s(b""), vec![1]].concat(), 0, 0),
            Err(WireError("an owner reply has bytes left over"))
        );
        decode_owner_names(&s(b""), 0, 0).unwrap_err();
    }
}
