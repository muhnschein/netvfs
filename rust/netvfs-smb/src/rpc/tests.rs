// SPDX-License-Identifier: LGPL-2.1-or-later
use std::time::Duration;

use super::*;
use crate::fake::{self, Peer, Req, created_body, pair};

const FID: FileId = [0x33; 16];
const IPC: Tree = Tree { id: 9, encrypt: false, share_type: 2 };

/// An NDR string as a server writes it.
fn string(w: &mut Writer, s: &str) {
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0);
    let n = u32::try_from(units.len()).unwrap();
    w.u32(n).u32(0).u32(n);
    for u in &units {
        w.u16(*u);
    }
    if units.len() % 2 == 1 {
        w.u16(0);
    }
}

/// A NetrShareEnum level 1 response stub.
pub(crate) fn enum_stub(entries: &[(Option<&str>, u32, Option<&str>)], werror: u32) -> Vec<u8> {
    let mut w = Writer::new();
    let n = u32::try_from(entries.len()).unwrap();
    w.u32(1).u32(1).u32(REFERENT).u32(n).u32(REFERENT).u32(n);
    for (name, share_type, remark) in entries {
        w.u32(if name.is_some() { REFERENT } else { 0 }).u32(*share_type);
        w.u32(if remark.is_some() { REFERENT } else { 0 });
    }
    for (name, _, remark) in entries {
        if let Some(name) = name {
            string(&mut w, name);
        }
        if let Some(remark) = remark {
            string(&mut w, remark);
        }
    }
    w.u32(n).u32(REFERENT).u32(0).u32(werror);
    w.into_vec()
}

fn pdu(ptype: u8, flags: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(5).u8(0).u8(ptype).u8(flags).bytes(&DREP);
    w.u16(u16::try_from(body.len().saturating_add(COMMON_LEN)).unwrap()).u16(0).u32(call_id).bytes(body);
    w.into_vec()
}

/// Response fragments of `stub`, `per` stub bytes each.
pub(crate) fn fragments(stub: &[u8], per: usize) -> Vec<u8> {
    let parts: Vec<&[u8]> = stub.chunks(per).collect();
    let last = parts.len().saturating_sub(1);
    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let mut flags = 0;
        if i == 0 {
            flags |= PFC_FIRST_FRAG;
        }
        if i == last {
            flags |= PFC_LAST_FRAG;
        }
        let mut body = Writer::new();
        body.u32(u32::try_from(stub.len()).unwrap()).u16(0).u8(0).u8(0).bytes(part);
        out.extend(pdu(PTYPE_RESPONSE, flags, ENUM_CALL, &body.into_vec()));
    }
    out
}

fn bind_ack(result: u16, transfer: &Syntax) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(4280).u16(4280).u32(0x1234);
    w.u16(13).bytes(b"\\PIPE\\srvsvc\0"); // secondary address; 16 + 8 + 2 + 13 = 39
    w.u8(0); // to 40
    w.u8(1).u8(0).u16(0).u16(result).u16(0).bytes(&transfer.0).u32(transfer.1);
    pdu(PTYPE_BIND_ACK, PFC_FIRST_FRAG | PFC_LAST_FRAG, BIND_CALL, &w.into_vec())
}

fn names(shares: &[ShareInfo]) -> Vec<&str> {
    shares.iter().map(|s| s.name.as_str()).collect()
}

#[test]
fn the_bind_and_the_request_are_c706_pdus() {
    let bind = bind_request().unwrap();
    assert_eq!(bind.len(), 72);
    assert_eq!(&bind[..4], &[5, 0, PTYPE_BIND, 3]);
    assert_eq!(&bind[4..8], &DREP);
    assert_eq!(u16::from_le_bytes([bind[8], bind[9]]), 72);
    assert_eq!(&bind[12..16], &BIND_CALL.to_le_bytes());
    assert_eq!(&bind[16..20], &[0xb8, 0x10, 0xb8, 0x10]);
    assert_eq!(&bind[32..48], &SRVSVC.0);
    assert_eq!(&bind[48..52], &[3, 0, 0, 0]);
    assert_eq!(&bind[52..68], &NDR.0);
    assert_eq!(&bind[68..72], &[2, 0, 0, 0]);
    let req = share_enum_request("srv").unwrap();
    assert_eq!(&req[..4], &[5, 0, PTYPE_REQUEST, 3]);
    assert_eq!(usize::from(u16::from_le_bytes([req[8], req[9]])), req.len());
    assert_eq!(&req[12..16], &ENUM_CALL.to_le_bytes());
    assert_eq!(&req[22..24], &OPNUM_NETR_SHARE_ENUM.to_le_bytes());
    let stub = &req[24..];
    assert_eq!(&req[16..20], &u32::try_from(stub.len()).unwrap().to_le_bytes());
    let mut w = Writer::new();
    w.u32(REFERENT).u32(6).u32(0).u32(6);
    for u in r"\\srv".encode_utf16().chain([0]) {
        w.u16(u);
    }
    w.u32(1).u32(1).u32(REFERENT).u32(0).u32(0).u32(u32::MAX).u32(REFERENT).u32(0);
    assert_eq!(stub, w.into_vec().as_slice());
    // A name the request cannot carry.
    share_enum_request(&"x".repeat(3000)).unwrap_err();
}

#[test]
fn a_bind_ack_must_accept_srvsvc_with_ndr() {
    check_bind_ack(&bind_ack(0, &NDR)).unwrap();
    let e = check_bind_ack(&bind_ack(2, &NDR)).unwrap_err();
    assert!(matches!(e, Error::Local(ref s) if s.name == ErrorName::Unsupported), "{e:?}");
    let ndr64: Syntax = ([0x33; 16], 1);
    assert!(matches!(check_bind_ack(&bind_ack(0, &ndr64)), Err(Error::Protocol(_))));
    let nak = pdu(PTYPE_BIND_NAK, 3, BIND_CALL, &[0, 0]);
    let e = check_bind_ack(&nak).unwrap_err();
    assert!(matches!(e, Error::Local(ref s) if s.name == ErrorName::Unsupported), "{e:?}");
    // Another call, a short PDU, no results, the wrong byte order, a
    // version 4 PDU, authentication data.
    let mut other = bind_ack(0, &NDR);
    other[12] = 7;
    let mut big_endian = bind_ack(0, &NDR);
    big_endian[4] = 0;
    let mut v4 = bind_ack(0, &NDR);
    v4[0] = 4;
    let mut auth = bind_ack(0, &NDR);
    auth[10] = 8;
    let mut none = bind_ack(0, &NDR);
    none[40] = 0;
    let full = bind_ack(0, &NDR);
    for bad in [other, big_endian, v4, auth, none, full[..full.len() - 1].to_vec(), full[..10].to_vec()] {
        assert!(matches!(check_bind_ack(&bad), Err(Error::Protocol(_))), "{bad:?}");
    }
    // A fault in reply to the bind.
    let fault = pdu(PTYPE_FAULT, 3, BIND_CALL, &[0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]);
    let e = check_bind_ack(&fault).unwrap_err();
    assert!(matches!(e, Error::Local(ref s) if s.message.contains("RPC fault 0x00000005")), "{e:?}");
}

#[test]
fn share_lists_decode_and_filter() {
    let stub = enum_stub(
        &[
            (Some("data"), 0, Some("Team files")),
            (Some("IPC$"), 0x8000_0003, Some("IPC Service")),
            (Some("C$"), 0x8000_0000, None),
            (Some("print"), 1, Some("")),
            (Some("bad/name"), 0, None),
            (None, 0, Some("nameless")),
            (Some("tabs"), 0, Some("a\tb\u{7f}c")),
        ],
        0,
    );
    let shares = decode_share_enum(&stub).unwrap();
    assert_eq!(names(&shares), ["data", "IPC$", "C$", "print", "tabs"]);
    assert_eq!(shares[0].remark, "Team files");
    assert_eq!(shares[4].remark, "abc");
    assert_eq!(shares[1].share_type, 0x8000_0003);
    let visible: Vec<&str> = shares.iter().filter(|s| s.visible(false)).map(|s| s.name.as_str()).collect();
    assert_eq!(visible, ["data", "tabs"]);
    let admin: Vec<&str> = shares.iter().filter(|s| s.visible(true)).map(|s| s.name.as_str()).collect();
    assert_eq!(admin, ["data", "C$", "tabs"]);
    // A long remark is cut.
    let long = "r".repeat(MAX_STRING_UNITS - 1);
    let shares = decode_share_enum(&enum_stub(&[(Some("a"), 0, Some(&long))], 0)).unwrap();
    assert_eq!(shares[0].remark.len(), MAX_REMARK);
    // Empty: no container, or no entries.
    let mut w = Writer::new();
    w.u32(1).u32(1).u32(0).u32(0).u32(0).u32(0);
    assert_eq!(decode_share_enum(&w.into_vec()).unwrap(), []);
    let mut w = Writer::new();
    w.u32(1).u32(1).u32(REFERENT).u32(0).u32(0).u32(0).u32(0).u32(0);
    assert_eq!(decode_share_enum(&w.into_vec()).unwrap(), []);
}

#[test]
fn malformed_share_lists_are_refused() {
    let good = enum_stub(&[(Some("data"), 0, Some("x"))], 0);
    // Every truncation.
    for n in 0..good.len() {
        assert!(decode_share_enum(&good[..n]).is_err(), "{n}");
    }
    let patch = |at: usize, v: u32| {
        let mut s = good.clone();
        s[at..at + 4].copy_from_slice(&v.to_le_bytes());
        s
    };
    let too_many = u32::try_from(MAX_SHARES).unwrap() + 1;
    let long = u32::try_from(MAX_STRING_UNITS).unwrap() + 1;
    let cases = [
        patch(0, 2),         // level
        patch(4, 2),         // union arm
        patch(12, too_many), // EntriesRead
        patch(20, 2),        // max_count differs
        patch(12, 2),        // EntriesRead differs
        patch(36, long),     // string max_count
        patch(40, 1),        // string offset
        patch(44, 6),        // actual_count above max_count
    ];
    for (i, bad) in cases.iter().enumerate() {
        assert!(matches!(decode_share_enum(bad), Err(Error::Protocol(_))), "case {i}");
    }
    // A count far beyond the bytes there are is refused before allocating.
    let mut w = Writer::new();
    w.u32(1).u32(1).u32(REFERENT).u32(4000).u32(REFERENT).u32(4000);
    decode_share_enum(&w.into_vec()).unwrap_err();
    // A null buffer with entries.
    let mut w = Writer::new();
    w.u32(1).u32(1).u32(REFERENT).u32(1).u32(0).u32(0).u32(0).u32(0);
    decode_share_enum(&w.into_vec()).unwrap_err();
    // Windows errors.
    let e = decode_share_enum(&enum_stub(&[], 5)).unwrap_err();
    assert!(matches!(e, Error::Local(ref s) if s.name == ErrorName::PermissionDenied), "{e:?}");
    let e = decode_share_enum(&enum_stub(&[], 1722)).unwrap_err();
    assert!(matches!(e, Error::Local(ref s) if s.message.ends_with("Windows error 1722")), "{e:?}");
    // A string without its NUL is taken as it is; a lone surrogate in a
    // name drops the entry.
    let mut w = Writer::new();
    w.u32(1).u32(1).u32(REFERENT).u32(2).u32(REFERENT).u32(2);
    w.u32(REFERENT).u32(0).u32(0).u32(REFERENT).u32(0).u32(0);
    w.u32(2).u32(0).u32(2).u16(u16::from(b'a')).u16(u16::from(b'b'));
    w.u32(1).u32(0).u32(1).u16(0xD800).u16(0);
    w.u32(2).u32(0).u32(0);
    assert_eq!(names(&decode_share_enum(&w.into_vec()).unwrap()), ["ab"]);
}

#[test]
fn fragments_reassemble_from_pieces_of_any_size() {
    let stub = enum_stub(&[(Some("data"), 0, Some("Team files")), (Some("more"), 0, None)], 0);
    let wire = fragments(&stub, 20);
    for piece in [1, 7, 24, 100, wire.len()] {
        let mut r = Reassembly::new();
        for part in wire.chunks(piece) {
            assert!(!r.done());
            r.feed(part).unwrap();
        }
        assert!(r.done(), "{piece}");
        assert_eq!(r.stub(), stub.as_slice());
    }
    // Bytes after the last fragment.
    let mut r = Reassembly::new();
    let mut extra = wire.clone();
    extra.push(0);
    assert!(r.feed(&extra).is_err());
    let mut r = Reassembly::new();
    r.feed(&wire).unwrap();
    assert!(r.feed(&[0]).is_err());
    r.feed(&[]).unwrap();
}

#[test]
fn bad_fragments_are_refused() {
    let stub = vec![0u8; 100];
    let wire = fragments(&stub, 40);
    let first_len = usize::from(u16::from_le_bytes([wire[8], wire[9]]));
    // A first fragment without FIRST, a middle one with it, another call,
    // a fault, a fragment shorter than the response header.
    let mut no_first = wire.clone();
    no_first[3] = 0;
    let mut twice = wire.clone();
    twice[first_len + 3] |= PFC_FIRST_FRAG;
    let mut other_call = wire;
    other_call[12] = 9;
    let fault = pdu(PTYPE_FAULT, 3, ENUM_CALL, &[0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x1c]);
    let short = pdu(PTYPE_RESPONSE, 3, ENUM_CALL, &[0, 0]);
    let header_only = pdu(PTYPE_RESPONSE, 3, ENUM_CALL, &[])[..10].to_vec();
    let mut tiny = pdu(PTYPE_RESPONSE, 3, ENUM_CALL, &[]);
    tiny[8] = 8;
    for (i, bad) in [no_first, twice, other_call, fault, short, tiny].iter().enumerate() {
        assert!(Reassembly::new().feed(bad).is_err(), "case {i}");
    }
    // An incomplete header waits for more.
    let mut r = Reassembly::new();
    r.feed(&header_only).unwrap();
    assert!(!r.done());
    // A stub above the cap.
    let big = vec![0u8; MAX_STUB + 1];
    let wire = fragments(&big, 60_000);
    assert!(matches!(Reassembly::new().feed(&wire), Err(Error::Protocol(m)) if m.contains("too long")));
}

fn ioctl_body(output: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(49).u16(0).u32(FSCTL_PIPE_TRANSCEIVE).bytes(&FID);
    w.u32(112).u32(0).u32(112).u32(u32::try_from(output.len()).unwrap()).u32(0).u32(0).bytes(output);
    w.into_vec()
}

fn read_body(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17).u8(80).u8(0).u32(u32::try_from(data.len()).unwrap()).u32(0).u32(0).bytes(data);
    w.into_vec()
}

/// The input of an IOCTL request.
fn ioctl_input(req: &Req) -> Vec<u8> {
    assert_eq!(req.command(), Command::Ioctl);
    let b = req.body();
    assert_eq!(&b[4..8], &FSCTL_PIPE_TRANSCEIVE.to_le_bytes());
    let len = usize::try_from(u32::from_le_bytes(b[28..32].try_into().unwrap())).unwrap();
    b[56..][..len].to_vec()
}

async fn started() -> (Conn, Peer) {
    let (client, peer) = pair().await;
    let conn = Conn::start(client, Duration::from_secs(5));
    conn.set_limits(1 << 20, true);
    conn.grant(64);
    (conn, peer)
}

/// Serves CREATE, bind and the request; the reply is split between the
/// IOCTL (BUFFER_OVERFLOW) and READs of `per_read` bytes.
pub(crate) async fn serve(peer: &mut Peer, reply: &[u8], per_read: usize) {
    let create = peer.recv_one().await;
    assert_eq!(create.command(), Command::Create);
    assert_eq!(create.header.tree_id, 9);
    peer.send(&[fake::response(&create, NtStatus::SUCCESS, &created_body(0x80, 0, FID), 1)], false).await;
    let bind = peer.recv_one().await;
    assert_eq!(ioctl_input(&bind), bind_request().unwrap());
    peer.send(&[fake::response(&bind, NtStatus::SUCCESS, &ioctl_body(&bind_ack(0, &NDR)), 1)], false).await;
    let call = peer.recv_one().await;
    assert_eq!(ioctl_input(&call), share_enum_request("srv").unwrap());
    let first = reply.len().min(MAX_FRAG);
    let status = if first < reply.len() { NtStatus::BUFFER_OVERFLOW } else { NtStatus::SUCCESS };
    peer.send(&[fake::response(&call, status, &ioctl_body(&reply[..first]), 1)], false).await;
    for part in reply[first..].chunks(per_read) {
        let read = peer.recv_one().await;
        assert_eq!(read.command(), Command::Read);
        peer.send(&[fake::response(&read, NtStatus::SUCCESS, &read_body(part), 1)], false).await;
    }
    let close = peer.recv_one().await;
    assert_eq!(close.command(), Command::Close);
    assert_eq!(&close.body()[8..24], &FID);
}

#[tokio::test]
async fn list_shares_binds_calls_and_reads_the_rest() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    let entries: Vec<(String, String)> =
        (0..300).map(|i| (format!("share{i}"), format!("remark {i}"))).collect();
    let refs: Vec<(Option<&str>, u32, Option<&str>)> =
        entries.iter().map(|(n, r)| (Some(n.as_str()), 0, Some(r.as_str()))).collect();
    let stub = enum_stub(&refs, 0);
    let reply = fragments(&stub, MAX_FRAG - RESPONSE_LEN);
    assert!(reply.len() > 2 * MAX_FRAG);
    let (r, ()) = tokio::join!(list_shares(&conn, &IPC, "srv", &c), serve(&mut peer, &reply, 1000));
    let shares = r.unwrap();
    assert_eq!(shares.len(), 300);
    assert_eq!((shares[299].name.as_str(), shares[299].remark.as_str()), ("share299", "remark 299"));
    // A small reply in the IOCTL alone.
    let reply = fragments(&enum_stub(&[(Some("one"), 0, None)], 0), 1000);
    let (r, ()) = tokio::join!(list_shares(&conn, &IPC, "srv", &c), serve(&mut peer, &reply, 1000));
    assert_eq!(names(&r.unwrap()), ["one"]);
}

#[tokio::test]
async fn list_shares_failures_close_the_pipe() {
    let (conn, mut peer) = started().await;
    let c = CancelToken::new();
    // No pipe.
    let (r, ()) = tokio::join!(list_shares(&conn, &IPC, "srv", &c), async {
        let create = peer.recv_one().await;
        peer.send(&[fake::error(&create, NtStatus::OBJECT_NAME_NOT_FOUND, 1)], false).await;
    });
    assert_eq!(r.unwrap_err(), Error::Status(NtStatus::OBJECT_NAME_NOT_FOUND));
    // The bind refused.
    let (r, ()) = tokio::join!(list_shares(&conn, &IPC, "srv", &c), async {
        let create = peer.recv_one().await;
        peer.send(&[fake::response(&create, NtStatus::SUCCESS, &created_body(0x80, 0, FID), 1)], false).await;
        let bind = peer.recv_one().await;
        let nak = pdu(PTYPE_BIND_NAK, 3, BIND_CALL, &[0, 0]);
        peer.send(&[fake::response(&bind, NtStatus::SUCCESS, &ioctl_body(&nak), 1)], false).await;
        let close = peer.recv_one().await;
        assert_eq!(close.command(), Command::Close);
    });
    assert!(matches!(r, Err(Error::Local(ref s)) if s.name == ErrorName::Unsupported), "{r:?}");
    // A READ with nothing.
    let (r, ()) = tokio::join!(list_shares(&conn, &IPC, "srv", &c), async {
        let create = peer.recv_one().await;
        peer.send(&[fake::response(&create, NtStatus::SUCCESS, &created_body(0x80, 0, FID), 1)], false).await;
        let bind = peer.recv_one().await;
        peer.send(&[fake::response(&bind, NtStatus::SUCCESS, &ioctl_body(&bind_ack(0, &NDR)), 1)], false)
            .await;
        let call = peer.recv_one().await;
        let reply = fragments(&enum_stub(&[(Some("one"), 0, None)], 0), 1000);
        peer.send(&[fake::response(&call, NtStatus::BUFFER_OVERFLOW, &ioctl_body(&reply[..30]), 1)], false)
            .await;
        let read = peer.recv_one().await;
        peer.send(&[fake::response(&read, NtStatus::SUCCESS, &read_body(&[]), 1)], false).await;
        let close = peer.recv_one().await;
        assert_eq!(close.command(), Command::Close);
    });
    assert!(matches!(r, Err(Error::Protocol(ref m)) if m.contains("no data")), "{r:?}");
}
