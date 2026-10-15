// SPDX-License-Identifier: LGPL-2.1-or-later
//! The share list of server mode (XM-7): NetrShareEnum level 1 (MS-SRVS
//! 3.1.4.8) on the `srvsvc` pipe of IPC$, over connection-oriented
//! DCE/RPC (C706 chapter 12, MS-RPCE 2.2.2) with NDR (C706 chapter 14).
//!
//! The PDU and NDR decoders are pure functions of bytes (fuzz target
//! `ndr_share_enum`). Every count is checked against the bytes that are
//! left before anything is allocated, the reply is capped at
//! [`MAX_STUB`] bytes and [`MAX_SHARES`] entries.

use netvfs_vfs::{CancelToken, ErrorName, Status};

use crate::conn::{Conn, Element};
use crate::error::{Error, Result, protocol};
use crate::msg::Command;
use crate::msg::file::{
    self, Create, FSCTL_PIPE_TRANSCEIVE, FileId, access, disposition, ioctl_request, ioctl_response,
};
use crate::names::{clean_text, valid_share_name};
use crate::session::Tree;
use crate::status::NtStatus;
use crate::wire::{Reader, Writer, from_u32, to_u16, to_u32};

/// The pipe.
pub const PIPE: &str = "srvsvc";
/// The fragment size this client sends and receives.
pub const MAX_FRAG: usize = 4280;
/// The stub of one reply, all fragments together.
pub const MAX_STUB: usize = 1024 * 1024;
/// Entries of the share list.
pub const MAX_SHARES: usize = 4096;
/// UTF-16 units of one string of the reply.
pub const MAX_STRING_UNITS: usize = 1024;
/// SHARE_INFO_1 remarks are kept to this many characters.
pub const MAX_REMARK: usize = 256;
/// SHARE_INFO_1 shi1_type: the low byte is the kind (MS-SRVS 2.2.2.4).
pub const SHARE_TYPE_MASK: u32 = 0xff;
/// STYPE_DISKTREE.
pub const SHARE_TYPE_DISK: u32 = 0;

const PTYPE_REQUEST: u8 = 0;
const PTYPE_RESPONSE: u8 = 2;
const PTYPE_FAULT: u8 = 3;
const PTYPE_BIND: u8 = 11;
const PTYPE_BIND_ACK: u8 = 12;
const PTYPE_BIND_NAK: u8 = 13;
const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
/// Little-endian integers, ASCII, IEEE floats.
const DREP: [u8; 4] = [0x10, 0, 0, 0];
/// The common header (C706 12.6.3.1).
const COMMON_LEN: usize = 16;
/// A response PDU's header: the common one, alloc_hint, p_cont_id,
/// cancel_count, reserved.
const RESPONSE_LEN: usize = 24;
/// NetrShareEnum.
const OPNUM_NETR_SHARE_ENUM: u16 = 15;
const BIND_CALL: u32 = 1;
const ENUM_CALL: u32 = 2;
/// A non-null unique pointer.
const REFERENT: u32 = 0x0002_0000;
/// The pipe's DesiredAccess: read, write, attributes, synchronize.
const PIPE_ACCESS: u32 = 0x0012_019F;
/// What one pipe READ asks for.
const READ_LEN: usize = MAX_FRAG;
/// Bytes read from the pipe for one reply at most.
const MAX_READ_TOTAL: usize = MAX_STUB + MAX_STUB / 8;
/// WERROR ERROR_ACCESS_DENIED.
const WERR_ACCESS_DENIED: u32 = 5;

/// An interface or transfer syntax: UUID (NDR byte order) and version.
type Syntax = ([u8; 16], u32);

/// srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0.
const SRVSVC: Syntax =
    ([0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88], 3);
/// NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.
const NDR: Syntax =
    ([0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60], 2);

/// One SHARE_INFO_1 entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareInfo {
    /// shi1_netname.
    pub name: String,
    /// shi1_type.
    pub share_type: u32,
    /// shi1_remark, cleaned (at most [`MAX_REMARK`] characters).
    pub remark: String,
}

impl ShareInfo {
    /// `shareVisible` (XM-7): disk shares only, `$` shares only when asked
    /// for.
    #[must_use]
    pub fn visible(&self, show_admin: bool) -> bool {
        self.share_type & SHARE_TYPE_MASK == SHARE_TYPE_DISK && (show_admin || !self.name.ends_with('$'))
    }
}

fn header(w: &mut Writer, ptype: u8, call_id: u32) {
    w.u8(5).u8(0).u8(ptype).u8(PFC_FIRST_FRAG | PFC_LAST_FRAG).bytes(&DREP);
    w.u16(0).u16(0).u32(call_id); // frag_length (set by `finish`), auth_length
}

/// Sets frag_length.
fn finish(w: Writer) -> Result<Vec<u8>> {
    let mut pdu = w.into_vec();
    let len = to_u16(pdu.len())?.to_le_bytes();
    if let Some(at) = pdu.get_mut(8..10) {
        at.copy_from_slice(&len);
    }
    Ok(pdu)
}

fn syntax(w: &mut Writer, s: &Syntax) {
    w.bytes(&s.0).u32(s.1);
}

/// The bind to srvsvc with NDR.
///
/// # Errors
/// Never in practice (sizes are fixed).
pub fn bind_request() -> Result<Vec<u8>> {
    let mut w = Writer::new();
    header(&mut w, PTYPE_BIND, BIND_CALL);
    let frag = to_u16(MAX_FRAG)?;
    w.u16(frag).u16(frag).u32(0); // max_xmit_frag, max_recv_frag, assoc_group_id
    w.u8(1).u8(0).u16(0); // one presentation context
    w.u16(0).u8(1).u8(0); // p_cont_id 0, one transfer syntax
    syntax(&mut w, &SRVSVC);
    syntax(&mut w, &NDR);
    finish(w)
}

/// A conformant varying string with its terminating NUL.
fn ndr_string(w: &mut Writer, text: &str) -> Result<()> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    units.push(0);
    let n = to_u32(units.len())?;
    w.u32(n).u32(0).u32(n);
    for u in &units {
        w.u16(*u);
    }
    if units.len() % 2 == 1 {
        w.u16(0); // to 4 bytes
    }
    Ok(())
}

/// NetrShareEnum(`\\host`, level 1, no limit).
///
/// # Errors
/// A server name too long for the PDU.
pub fn share_enum_request(host: &str) -> Result<Vec<u8>> {
    let mut stub = Writer::new();
    stub.u32(REFERENT); // ServerName
    ndr_string(&mut stub, &format!(r"\\{host}"))?;
    stub.u32(1).u32(1).u32(REFERENT); // Level, union switch, the container
    stub.u32(0).u32(0); // EntriesRead, Buffer (null)
    stub.u32(u32::MAX); // PreferedMaximumLength
    stub.u32(REFERENT).u32(0); // ResumeHandle
    let stub = stub.into_vec();
    if stub.len() > MAX_FRAG.saturating_sub(RESPONSE_LEN) {
        return Err(protocol("the server name is too long for the share list request"));
    }
    let mut w = Writer::new();
    header(&mut w, PTYPE_REQUEST, ENUM_CALL);
    w.u32(to_u32(stub.len())?).u16(0).u16(OPNUM_NETR_SHARE_ENUM).bytes(&stub);
    finish(w)
}

/// The common header of a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Common {
    ptype: u8,
    flags: u8,
    frag_len: usize,
    call_id: u32,
}

/// The common header at the start of `pdu`; refuses another version, a
/// byte order other than little-endian, authentication data and a
/// fragment shorter than its header.
fn common(pdu: &[u8]) -> Result<Common> {
    let mut r = Reader::new(pdu);
    let (major, minor) = (r.u8()?, r.u8()?);
    let (ptype, flags) = (r.u8()?, r.u8()?);
    let drep = r.array::<4>()?;
    let frag_len = usize::from(r.u16()?);
    let auth_len = r.u16()?;
    let call_id = r.u32()?;
    if major != 5 || minor != 0 {
        return Err(protocol(format!("RPC version {major}.{minor}")));
    }
    if drep.first().is_none_or(|d| d & 0xF0 != 0x10) {
        return Err(protocol("an RPC reply in big-endian byte order"));
    }
    if auth_len != 0 {
        return Err(protocol("an RPC reply with authentication data"));
    }
    if frag_len < COMMON_LEN {
        return Err(protocol("an RPC fragment shorter than its header"));
    }
    Ok(Common { ptype, flags, frag_len, call_id })
}

/// A fault or reject as an error.
fn refused(pdu: &[u8], c: &Common, what: &str) -> Error {
    if c.ptype == PTYPE_FAULT {
        let mut r = Reader::new(pdu);
        let status = r.seek(RESPONSE_LEN).and_then(|()| r.u32()).unwrap_or(0);
        return Error::Local(Status::new(
            ErrorName::ProtocolError,
            format!("Cannot list the shares: the server refused the {what} (RPC fault 0x{status:08x})"),
        ));
    }
    if c.ptype == PTYPE_BIND_NAK {
        return Error::Local(Status::new(
            ErrorName::Unsupported,
            "Cannot list the shares: the server refused the RPC bind to srvsvc",
        ));
    }
    protocol(format!("RPC PDU type {} in reply to the {what}", c.ptype))
}

/// Checks a bind_ack (C706 12.6.4.4): the call, one fragment, srvsvc
/// accepted with NDR.
///
/// # Errors
/// A refusal, a malformed or mismatched PDU.
pub fn check_bind_ack(pdu: &[u8]) -> Result<()> {
    let c = common(pdu)?;
    if c.ptype != PTYPE_BIND_ACK {
        return Err(refused(pdu, &c, "bind"));
    }
    if c.call_id != BIND_CALL || c.flags & PFC_LAST_FRAG == 0 || c.frag_len != pdu.len() {
        return Err(protocol("a malformed RPC bind_ack"));
    }
    let mut r = Reader::new(pdu);
    r.seek(COMMON_LEN)?;
    r.skip(8)?; // max_xmit_frag, max_recv_frag, assoc_group_id
    let port_len = usize::from(r.u16()?);
    r.skip(port_len)?;
    r.seek(r.pos().next_multiple_of(4))?;
    let results = r.u8()?;
    r.skip(3)?;
    if results == 0 {
        return Err(protocol("an RPC bind_ack without results"));
    }
    let result = r.u16()?;
    r.skip(2)?; // reason
    let transfer: Syntax = (r.array()?, r.u32()?);
    if result != 0 {
        return Err(Error::Local(Status::new(
            ErrorName::Unsupported,
            format!("Cannot list the shares: the server refused srvsvc (RPC result {result})"),
        )));
    }
    if transfer != NDR {
        return Err(protocol("the RPC bind_ack names a transfer syntax other than NDR"));
    }
    Ok(())
}

/// Collects the fragments of one response from what the pipe gives, in
/// pieces of any size.
#[derive(Debug, Default)]
pub struct Reassembly {
    pending: Vec<u8>,
    stub: Vec<u8>,
    fragments: usize,
    done: bool,
}

impl Reassembly {
    /// A new, empty reply.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the last fragment is in.
    #[must_use]
    pub const fn done(&self) -> bool {
        self.done
    }

    /// The stub, once [`Self::done`].
    #[must_use]
    pub fn stub(&self) -> &[u8] {
        &self.stub
    }

    /// Takes more bytes of the pipe.
    ///
    /// # Errors
    /// Bytes after the last fragment, a fault, a fragment of another call
    /// or out of order, a stub above [`MAX_STUB`].
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.done && !data.is_empty() {
            return Err(protocol("data after the last RPC fragment"));
        }
        self.pending.extend_from_slice(data);
        while !self.done && self.pending.len() >= COMMON_LEN {
            let c = common(&self.pending)?;
            if self.pending.len() < c.frag_len {
                break;
            }
            let rest = self.pending.split_off(c.frag_len);
            let pdu = std::mem::replace(&mut self.pending, rest);
            self.fragment(&pdu, &c)?;
        }
        if self.done && !self.pending.is_empty() {
            return Err(protocol("data after the last RPC fragment"));
        }
        Ok(())
    }

    fn fragment(&mut self, pdu: &[u8], c: &Common) -> Result<()> {
        if c.ptype != PTYPE_RESPONSE {
            return Err(refused(pdu, c, "share list request"));
        }
        if c.call_id != ENUM_CALL {
            return Err(protocol("an RPC response to another call"));
        }
        let first = c.flags & PFC_FIRST_FRAG != 0;
        if first != (self.fragments == 0) {
            return Err(protocol("RPC response fragments out of order"));
        }
        let stub =
            pdu.get(RESPONSE_LEN..).ok_or_else(|| protocol("an RPC response shorter than its header"))?;
        if self.stub.len().saturating_add(stub.len()) > MAX_STUB {
            return Err(protocol("the share list is too long"));
        }
        self.stub.extend_from_slice(stub);
        self.fragments = self.fragments.saturating_add(1);
        self.done = c.flags & PFC_LAST_FRAG != 0;
        Ok(())
    }
}

/// NDR reader: 4-byte alignment from the stub's start.
struct Ndr<'a>(Reader<'a>);

impl Ndr<'_> {
    fn u32(&mut self) -> Result<u32> {
        let at = self.0.pos().next_multiple_of(4);
        self.0.seek(at)?;
        self.0.u32()
    }

    fn count(&mut self, max: usize, what: &str) -> Result<usize> {
        let n = from_u32(self.u32()?)?;
        if n > max {
            return Err(protocol(format!("the share list has {n} {what}, more than {max}")));
        }
        Ok(n)
    }

    /// A conformant varying string; the terminating NUL dropped.
    fn string(&mut self) -> Result<Vec<u16>> {
        let max = self.count(MAX_STRING_UNITS, "characters in a string")?;
        let offset = self.u32()?;
        let actual = self.count(max, "characters in a string")?;
        if offset != 0 {
            return Err(protocol("an NDR string with an offset"));
        }
        let bytes = self.0.bytes(actual.saturating_mul(2))?;
        let mut units: Vec<u16> =
            bytes.chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap_or_default())).collect();
        if units.last() == Some(&0) {
            units.pop();
        }
        Ok(units)
    }
}

/// shi1_netname, shi1_type and shi1_remark as sent.
type RawShare = (Option<Vec<u16>>, u32, Option<Vec<u16>>);

/// Decodes the stub of a NetrShareEnum level 1 response (MS-SRVS
/// 2.2.4.38, 3.1.4.8). Entries whose name is not a usable share name are
/// left out.
///
/// # Errors
/// A malformed stub, more than [`MAX_SHARES`] entries, a Windows error.
pub fn decode_share_enum(stub: &[u8]) -> Result<Vec<ShareInfo>> {
    let mut r = Ndr(Reader::new(stub));
    let level = r.u32()?;
    let switch = r.u32()?;
    if level != 1 || switch != 1 {
        return Err(protocol(format!("a share list of level {level}/{switch}, not 1")));
    }
    let mut raw: Vec<RawShare> = Vec::new();
    if r.u32()? != 0 {
        let entries = r.count(MAX_SHARES, "entries")?;
        if r.u32()? != 0 {
            let max = r.count(MAX_SHARES, "entries")?;
            if max != entries {
                return Err(protocol("the share list's counts differ"));
            }
            // 12 bytes per element, checked before the vector is made.
            if r.0.remaining() < max.saturating_mul(12) {
                return Err(protocol("the share list is shorter than its count"));
            }
            let mut fixed = Vec::with_capacity(max);
            for _ in 0..max {
                fixed.push((r.u32()? != 0, r.u32()?, r.u32()? != 0));
            }
            for (has_name, share_type, has_remark) in fixed {
                let name = if has_name { Some(r.string()?) } else { None };
                let remark = if has_remark { Some(r.string()?) } else { None };
                raw.push((name, share_type, remark));
            }
        } else if entries != 0 {
            return Err(protocol("a share list without its entries"));
        }
    }
    r.u32()?; // TotalEntries
    if r.u32()? != 0 {
        r.u32()?; // ResumeHandle
    }
    match r.u32()? {
        0 => {}
        WERR_ACCESS_DENIED => {
            return Err(Error::Local(Status::new(
                ErrorName::PermissionDenied,
                "Cannot list the shares: access denied (Windows error 5)",
            )));
        }
        e => {
            return Err(Error::Local(Status::new(
                ErrorName::ProtocolError,
                format!("Cannot list the shares: Windows error {e}"),
            )));
        }
    }
    Ok(raw
        .into_iter()
        .filter_map(|(name, share_type, remark)| {
            let name = String::from_utf16(&name?).ok().filter(|n| valid_share_name(n))?;
            let remark =
                remark.map(|u| clean_text(&String::from_utf16_lossy(&u), MAX_REMARK)).unwrap_or_default();
            Some(ShareInfo { name, share_type, remark })
        })
        .collect())
}

/// The pipe, open on IPC$.
struct Pipe<'a> {
    conn: &'a Conn,
    tree: &'a Tree,
    file_id: FileId,
}

impl Pipe<'_> {
    /// One IOCTL transceive: `pdu` in, the start of the reply out
    /// (BUFFER_OVERFLOW: more to READ).
    async fn transceive(&self, pdu: &[u8], cancel: &CancelToken) -> Result<Vec<u8>> {
        let body = ioctl_request(FSCTL_PIPE_TRANSCEIVE, &self.file_id, pdu, MAX_FRAG)?;
        let resp = self.conn.call(self.tree.target(), Element::new(Command::Ioctl, body), cancel).await?;
        resp.expect(&[NtStatus::BUFFER_OVERFLOW])?;
        Ok(ioctl_response(&resp.msg, MAX_FRAG)?.to_vec())
    }

    async fn read(&self, cancel: &CancelToken) -> Result<Vec<u8>> {
        let body = file::read_request(&self.file_id, 0, READ_LEN)?;
        let element = Element::new(Command::Read, body).payload(READ_LEN);
        let resp = self.conn.call(self.tree.target(), element, cancel).await?;
        resp.expect(&[NtStatus::BUFFER_OVERFLOW])?;
        let data = file::read_response(&resp.msg, READ_LEN)?;
        if data.is_empty() {
            return Err(protocol("the srvsvc pipe gave no data"));
        }
        Ok(data.to_vec())
    }

    /// A whole call: `pdu` out, the reply's fragments in.
    async fn call(&self, pdu: &[u8], cancel: &CancelToken) -> Result<Vec<u8>> {
        let mut reply = Reassembly::new();
        let first = self.transceive(pdu, cancel).await?;
        let mut total = first.len();
        reply.feed(&first)?;
        while !reply.done() {
            let more = self.read(cancel).await?;
            total = total.saturating_add(more.len());
            if total > MAX_READ_TOTAL {
                return Err(protocol("the share list is too long"));
            }
            reply.feed(&more)?;
        }
        Ok(reply.stub().to_vec())
    }

    async fn bind(&self, cancel: &CancelToken) -> Result<()> {
        let mut pdu = self.transceive(&bind_request()?, cancel).await?;
        // A bind_ack fits one fragment; more is read only to report it.
        while pdu.len() < COMMON_LEN || common(&pdu)?.frag_len > pdu.len() {
            if pdu.len() > MAX_FRAG {
                break;
            }
            pdu.extend(self.read(cancel).await?);
        }
        check_bind_ack(&pdu)
    }
}

/// The shares of the server (XM-7), over `ipc`, a tree of IPC$.
///
/// # Errors
/// The server's refusals, malformed replies, the connection's failures.
pub async fn list_shares(
    conn: &Conn,
    ipc: &Tree,
    host: &str,
    cancel: &CancelToken,
) -> Result<Vec<ShareInfo>> {
    let name: Vec<u16> = PIPE.encode_utf16().collect();
    let create = Create {
        name: &name,
        access: PIPE_ACCESS | access::SYNCHRONIZE,
        attributes: 0,
        disposition: disposition::OPEN,
        options: 0,
    };
    let resp =
        conn.call(ipc.target(), Element::new(Command::Create, create.encode()?).owning(), cancel).await?;
    resp.ok()?;
    let file_id = file::Created::decode(&resp.msg)?.file_id;
    let pipe = Pipe { conn, tree: ipc, file_id };
    let result = async {
        pipe.bind(cancel).await?;
        let stub = pipe.call(&share_enum_request(host)?, cancel).await?;
        decode_share_enum(&stub)
    }
    .await;
    // The pipe is closed either way; its answer does not change the list.
    conn.close_detached(ipc.target(), &file_id);
    result
}

#[cfg(test)]
pub(crate) mod tests;
