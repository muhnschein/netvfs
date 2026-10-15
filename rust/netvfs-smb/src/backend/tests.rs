// SPDX-License-Identifier: LGPL-2.1-or-later
use std::time::Duration;

use netvfs_vfs::{Entry, ListSink};

use super::*;
use crate::fake::{self, FT, Peer, Req, close_body, created_body, four, pair};
use crate::msg::file::FileId;
use crate::negotiate::Negotiated;
use crate::wire::Writer;

const T: Duration = Duration::from_secs(5);
const FID: FileId = [0x44; 16];
const MS: i64 = 1_609_459_200_000;

fn params(options: &[(&str, Value)]) -> Params {
    Params {
        provider: "smb".into(),
        host: "srv".into(),
        options: options.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect(),
        ..Params::default()
    }
}

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

/// A backend signed in on the fake server: `max_io` bytes per READ and
/// WRITE, IPC$ (server mode) or the share as tree 9.
async fn signed(options: &[(&str, Value)], max_io: usize) -> (Smb, Peer) {
    let (client, peer) = pair().await;
    let conn = Conn::start(client, T);
    conn.set_limits(16 << 20, true);
    conn.grant(512);
    conn.establish(None, false);
    let negotiated = Negotiated {
        dialect: 0x0311,
        cipher: None,
        max_read: max_io,
        max_write: max_io,
        max_transact: 65_536,
        multi_credit: true,
        server_signing_required: false,
        server_guid: [0; 16],
    };
    let session = Session { conn, negotiated, flags: 0 };
    (Smb::signed_in_with(params(options), session, Tree { id: 9, encrypt: false, share_type: 2 }), peer)
}

fn share_mode() -> [(&'static str, Value); 1] {
    [("share", s("data"))]
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

/// Answers the next TREE_CONNECT with `tree_id`; returns its path.
async fn tree_connect(peer: &mut Peer, tree_id: u32) -> String {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::TreeConnect);
    let body = [16, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x01, 0x1f, 0x00];
    let mut msg = fake::response(&req, NtStatus::SUCCESS, &body, 1);
    msg[36..40].copy_from_slice(&tree_id.to_le_bytes());
    peer.send(&[msg], false).await;
    unc(&req)
}

fn unc(req: &Req) -> String {
    let b = req.body();
    let len = usize::from(u16::from_le_bytes([b[6], b[7]]));
    String::from_utf16(&b[8..][..len].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())
        .unwrap()
}

/// Refuses the next TREE_CONNECT.
async fn tree_refused(peer: &mut Peer, status: NtStatus) {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::TreeConnect);
    peer.send(&[fake::error(&req, status, 1)], false).await;
}

/// Answers a CREATE + CLOSE chain with `attributes` and `size`; returns
/// the tree and the CREATE's name.
async fn stat_chain(peer: &mut Peer, attributes: u32, size: u64) -> (u32, Vec<u16>) {
    let reqs = peer.recv().await;
    let cmds: Vec<Command> = reqs.iter().map(Req::command).collect();
    assert_eq!(cmds, [Command::Create, Command::Close]);
    let msgs = vec![
        fake::response(&reqs[0], NtStatus::SUCCESS, &created_body(attributes, size, FID), 1),
        fake::response(&reqs[1], NtStatus::SUCCESS, &close_body(), 1),
    ];
    peer.send(&fake::chain(msgs), false).await;
    (reqs[0].header.tree_id, create_name(&reqs[0]))
}

fn create_name(req: &Req) -> Vec<u16> {
    let b = req.body();
    let len = usize::from(u16::from_le_bytes([b[46], b[47]]));
    b[56..][..len].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

/// Disposition and options of a CREATE.
fn create_of(req: &Req) -> (u32, u32, u32) {
    let b = req.body();
    (le32(&b[24..28]), le32(&b[36..40]), le32(&b[40..44]))
}

/// Answers one CREATE; returns it.
async fn create(peer: &mut Peer, status: NtStatus, attributes: u32, size: u64) -> Req {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::Create);
    let msg = if status == NtStatus::SUCCESS {
        fake::response(&req, status, &created_body(attributes, size, FID), 1)
    } else {
        fake::error(&req, status, 1)
    };
    peer.send(&[msg], false).await;
    req
}

async fn answer_close(peer: &mut Peer) {
    let req = peer.recv_one().await;
    assert_eq!(req.command(), Command::Close);
    peer.send(&[fake::response(&req, NtStatus::SUCCESS, &close_body(), 1)], false).await;
}

fn byte(offset: u64) -> u8 {
    offset.to_le_bytes()[0] ^ 0xa5
}

fn content(from: u64, to: u64) -> Vec<u8> {
    (from..to).map(byte).collect()
}

fn read_body(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17).u8(80).u8(0).u32(u32::try_from(data.len()).unwrap()).u32(0).u32(0).bytes(data);
    w.into_vec()
}

fn write_body(count: usize) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17).u16(0).u32(u32::try_from(count).unwrap()).u32(0).u16(0).u16(0);
    w.into_vec()
}

/// Receives `n` READs, then answers them from a file of `size` bytes.
async fn serve_reads(peer: &mut Peer, size: u64, n: usize) -> Vec<(u64, usize)> {
    let mut reqs = Vec::new();
    for _ in 0..n {
        reqs.push(peer.recv_one().await);
    }
    let mut seen = Vec::new();
    for req in &reqs {
        assert_eq!(req.command(), Command::Read);
        let b = req.body();
        let (offset, count) = (le64(&b[8..16]), usize::try_from(le32(&b[4..8])).unwrap());
        seen.push((offset, count));
        let end = size.min(offset.saturating_add(u64::try_from(count).unwrap()));
        let msg = fake::response(req, NtStatus::SUCCESS, &read_body(&content(offset, end)), 1);
        peer.send(&[msg], false).await;
    }
    seen
}

#[derive(Default)]
struct Names {
    batches: Vec<Vec<String>>,
    stop_after: Option<usize>,
}

impl ListSink for Names {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        assert!(batch.iter().all(|e| e.kind == EntryType::Directory));
        self.batches.push(batch.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()).collect());
        self.stop_after.is_none_or(|n| self.batches.len() < n)
    }
}

#[derive(Default)]
struct Moves {
    updates: Vec<(u64, Option<u64>)>,
    cancel_after: Option<usize>,
}

impl Progress for Moves {
    fn update(&mut self, done: u64, total: Option<u64>) {
        self.updates.push((done, total));
    }

    fn canceled(&mut self) -> bool {
        self.cancel_after.is_some_and(|n| self.updates.len() >= n)
    }
}

struct Bytes {
    data: Vec<u8>,
    at: usize,
    fail: bool,
}

impl Source for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, Status> {
        if self.fail && self.at > 0 {
            return Err(Status::internal("the local file went"));
        }
        let rest = &self.data[self.at..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.at = self.at.saturating_add(n);
        Ok(n)
    }

    fn size(&self) -> Option<u64> {
        Some(u64::try_from(self.data.len()).unwrap())
    }
}

#[derive(Default)]
struct Collected(Vec<u8>);

impl Sink for Collected {
    fn write(&mut self, data: &[u8]) -> std::result::Result<(), Status> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

#[test]
fn helpers() {
    assert!(representable(None));
    assert!(representable(Some(1000)));
    assert!(representable(Some(910_692_730_084_999)));
    for ms in [999, 0, -1, 910_692_730_085_000, i64::MAX, i64::MIN] {
        assert!(!representable(Some(ms)), "{ms}");
    }
    assert_eq!(timeout_of(0, 7), Duration::from_millis(7));
    assert_eq!(timeout_of(-5, 7), Duration::from_millis(7));
    assert_eq!(timeout_of(250, 7), Duration::from_millis(250));
    let p = params(&[("a", s("1")), ("b", s("no"))]);
    assert!(flag_or(&p, "a", false));
    assert!(!flag_or(&p, "b", true));
    assert!(flag_or(&p, "c", true));
    assert!(!flag_or(&p, "c", false));
    let p = params(&[("shares", s(" b, A,,bad/x , a,b "))]);
    assert_eq!(configured_shares(&p), ["b", "A"]);
    let p = params(&[("shares", Value::StrList(vec!["x".into(), " y ".into(), "X".into(), "?".into()]))]);
    assert_eq!(configured_shares(&p), ["x", "y"]);
    assert_eq!(configured_shares(&params(&[])), Vec::<String>::new());
    let mut list = vec!["Data".to_owned()];
    merge_share_names(&mut list, ["data".to_owned(), "Ünï".to_owned(), "ÜNÏ".to_owned()]);
    assert_eq!(list, ["Data", "Ünï"]);
}

#[tokio::test]
async fn nothing_works_before_sign_in() {
    let c = CancelToken::new();
    let mut smb = Smb::new();
    assert_eq!(smb.capabilities(), Capabilities::default());
    let e = smb.stat(b"/x", true, &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Internal, "Not signed in"));
    // Names are checked first.
    assert_eq!(smb.stat(b"/a/../b", true, &c).await.unwrap_err().name, ErrorName::InvalidName);
    assert_eq!(smb.keep_alive(&c).await.unwrap_err().message, "Not signed in");
    let e = smb.authenticate(&Credentials::default(), None, &c).await.unwrap_err();
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::Internal, "authenticate() needs a successful connect()")
    );
    // A port nothing listens on, one out of range.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let mut p = params(&[]);
    p.host = "127.0.0.1".into();
    p.port = i32::from(closed.port());
    let e = smb.connect(&p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NetworkUnreachable);
    assert!(e.message.starts_with("Cannot connect to the server: "), "{e:?}");
    p.port = 70_000;
    let e = smb.connect(&p, &c).await.unwrap_err();
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::NetworkUnreachable, "Cannot connect to the server: port 70000 is out of range")
    );
    // Connected: the credentials and options are checked before the
    // session starts.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    p.port = i32::from(listener.local_addr().unwrap().port());
    assert_eq!(smb.connect(&p, &c).await, Ok(None));
    let user = |user: &str, secret: &[u8]| Credentials {
        user: user.into(),
        secret: Zeroizing::new(secret.to_vec()),
        domain: String::new(),
    };
    for credentials in [user("", b"pw"), user("u", b"")] {
        let e = smb.authenticate(&credentials, None, &c).await.unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::AuthFailed, "A user name and a password are required")
        );
    }
    let e = smb.authenticate(&user("u", b"\xff"), None, &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::AuthFailed, "The password is not valid UTF-8"));
    p.options.insert("security_profile".into(), s("legacy"));
    smb.connect(&p, &c).await.unwrap();
    let e = smb.authenticate(&user("u", b"pw"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy);
    p.options.insert("security_profile".into(), s("strict"));
    p.options.insert("share".into(), s("a:b"));
    smb.connect(&p, &c).await.unwrap();
    assert_eq!(smb.authenticate(&user("u", b"pw"), None, &c).await.unwrap_err().name, ErrorName::InvalidName);
    // A server that closes at once: the sign-in is refused (M-T7).
    p.options.remove("share");
    tokio::spawn(async move {
        loop {
            drop(listener.accept().await);
        }
    });
    smb.connect(&p, &c).await.unwrap();
    let e = smb.authenticate(&user("u", b"pw"), None, &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::SecurityPolicy, crate::error::SERVER_CLOSED));
    // A tripped token.
    let tripped = CancelToken::new();
    tripped.cancel();
    smb.connect(&p, &c).await.unwrap();
    assert_eq!(
        smb.authenticate(&user("u", b"pw"), None, &tripped).await.unwrap_err().name,
        ErrorName::Canceled
    );
}

#[tokio::test]
async fn capabilities_by_mode() {
    let (smb, _peer) = signed(&share_mode(), 1 << 20).await;
    let caps = smb.capabilities();
    assert_eq!(
        caps.names(),
        [
            "AtomicReplace",
            "CaseInsensitive",
            "EfficientRanges",
            "NativeNoReplace",
            "ReadHandles",
            "SetModified",
            "SetModifiedOnUpload",
            "SpaceInfo",
            "WindowsNames",
            "WriteResume"
        ]
    );
    assert_eq!(caps.max_name_bytes, Some(255));
    let (smb, _peer) = signed(&[], 1 << 20).await;
    assert!(smb.capabilities().has(Capability::ShareEnumeration));
    let (smb, _peer) = signed(&[("share_enumeration", s("false"))], 1 << 20).await;
    assert!(!smb.capabilities().has(Capability::ShareEnumeration));
    assert!(smb.capabilities().has(Capability::SpaceInfo));
}

#[tokio::test]
async fn paths_name_the_share_and_the_path() {
    let (smb, _peer) = signed(&[], 1 << 20).await;
    let place = smb.split(b"/data/a/b").unwrap();
    assert_eq!(place, Place { share: Some("data".into()), path: utf16(r"a\b"), name: b"b".to_vec() });
    assert_eq!(
        smb.split(b"//data//").unwrap(),
        Place { share: Some("data".into()), path: vec![], name: b"data".to_vec() }
    );
    assert_eq!(smb.split(b"/").unwrap(), Place { share: None, path: vec![], name: vec![] });
    for bad in [&b"/a:b/x"[..], b"/da\xfft/x", b"/a/\0", b"/a/../b", b"/a/b\xff"] {
        assert_eq!(smb.split(bad).unwrap_err().name, ErrorName::InvalidName, "{bad:?}");
    }
    // M-9: a name Windows cannot store.
    assert_eq!(smb.split(b"/a/b?").unwrap_err().name, ErrorName::Internal);
    assert!(smb.share_level(b"/"));
    assert!(smb.share_level(b"/data"));
    assert!(!smb.share_level(b"/data/x"));
    let (smb, _peer) = signed(&share_mode(), 1 << 20).await;
    assert_eq!(
        smb.split(b"/a/b").unwrap(),
        Place { share: Some("data".into()), path: utf16(r"a\b"), name: b"b".to_vec() }
    );
    assert_eq!(smb.split(b"/").unwrap(), Place { share: Some("data".into()), path: vec![], name: vec![] });
    assert!(!smb.share_level(b"/"));
    assert!(!smb.share_level(b"/a"));
}

#[tokio::test]
async fn the_server_root_holds_only_the_shares() {
    let (mut smb, _peer) = signed(&[], 1 << 20).await;
    let c = CancelToken::new();
    let root = smb.stat(b"/", true, &c).await.unwrap();
    assert_eq!((root.kind, root.name.len()), (EntryType::Directory, 0));
    let denied =
        |what: &str| Status::permission_denied(format!("{what}: the server root holds only the shares"));
    assert_eq!(smb.make_dir(b"/", true, &c).await, Err(denied("create folder")));
    assert_eq!(smb.remove_file(b"/", &c).await, Err(denied("remove")));
    assert_eq!(smb.remove_dir(b"/", &c).await, Err(denied("remove folder")));
    assert_eq!(smb.space_info(b"/", &c).await, Err(denied("free space")));
    assert_eq!(smb.open_read(b"/", &c).await.unwrap_err(), denied("open"));
    let options = WriteOptions::default();
    assert_eq!(smb.open_write(b"/", &options, &c).await.unwrap_err(), denied("open"));
    assert_eq!(smb.open_write(b"/data", &options, &c).await.unwrap_err(), denied("open"));
    let changes = Attributes { mtime_ms: Some(MS), ..Attributes::default() };
    assert_eq!(smb.set_attributes(b"/", &changes, &c).await, Err(denied("set attributes")));
    let mut sink = Collected::default();
    let mut progress = Moves::default();
    assert_eq!(smb.download(b"/", 0, None, &mut sink, &mut progress, &c).await, Err(denied("download")));
    let share_denied = Status::permission_denied("rename: a share cannot be removed or renamed");
    assert_eq!(smb.rename(b"/a", b"/a/b", RenameMode::Replace, &c).await, Err(share_denied.clone()));
    assert_eq!(smb.rename(b"/a/b", b"/", RenameMode::NoReplace, &c).await, Err(share_denied));
    // XC-11: every field first, before any request.
    let mode = Attributes { mode: Some(0o644), ..Attributes::default() };
    assert_eq!(
        smb.set_attributes(b"/a/b", &mode, &c).await.unwrap_err().message,
        "SMB has no permission bits"
    );
    for changes in [
        Attributes { mtime_ms: Some(-1), ..Attributes::default() },
        Attributes { atime_ms: Some(i64::MAX), ..Attributes::default() },
    ] {
        let e = smb.set_attributes(b"/a/b", &changes, &c).await.unwrap_err();
        assert_eq!((e.name, e.message.as_str()), (ErrorName::Unsupported, TIMES_UNSUPPORTED));
    }
    let late = WriteOptions { mtime_ms: Some(0), ..WriteOptions::default() };
    assert_eq!(smb.open_write(b"/a/b", &late, &c).await.unwrap_err().message, TIMES_UNSUPPORTED);
}

#[tokio::test]
async fn shares_connect_on_demand_and_the_oldest_goes() {
    let (mut smb, mut peer) = signed(&[], 1 << 20).await;
    let c = CancelToken::new();
    for (i, share) in ["s1", "s2", "s3", "s4"].iter().enumerate() {
        let id = u32::try_from(i).unwrap().saturating_add(20);
        let path = format!("/{share}/f");
        let (r, ()) = tokio::join!(smb.stat(path.as_bytes(), true, &c), async {
            assert_eq!(tree_connect(&mut peer, id).await, format!(r"\\srv\{share}"));
            assert_eq!(stat_chain(&mut peer, 0x20, 5).await, (id, utf16("f")));
        });
        assert_eq!(r.unwrap().name, b"f");
    }
    // The share itself: its name; the tree is reused, ignoring case.
    let (r, ()) = tokio::join!(smb.stat(b"/S1", true, &c), async {
        assert_eq!(stat_chain(&mut peer, 0x10, 0).await, (20, vec![]));
    });
    let e = r.unwrap();
    assert_eq!((e.name.as_slice(), e.kind), (&b"S1"[..], EntryType::Directory));
    // A fifth share: s2, the least recently used, is disconnected.
    let (r, ()) = tokio::join!(smb.stat(b"/s5/f", true, &c), async {
        let gone = peer.recv_one().await;
        assert_eq!((gone.command(), gone.header.tree_id), (Command::TreeDisconnect, 21));
        peer.send(&[fake::response(&gone, NtStatus::SUCCESS, &four(), 1)], false).await;
        assert_eq!(tree_connect(&mut peer, 24).await, r"\\srv\s5");
        stat_chain(&mut peer, 0x20, 5).await;
    });
    r.unwrap();
    // Files open on all four: no fifth.
    let mut handles = Vec::new();
    for (share, id) in [("s1", 20), ("s3", 22), ("s4", 23), ("s5", 24)] {
        let path = format!("/{share}/f");
        let (r, req) =
            tokio::join!(smb.open_read(path.as_bytes(), &c), create(&mut peer, NtStatus::SUCCESS, 0x20, 5));
        assert_eq!(req.header.tree_id, id);
        handles.push(r.unwrap());
    }
    let e = smb.stat(b"/s6/f", true, &c).await.unwrap_err();
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::TooManyConnections, "Files are open on 4 shares already; close some first")
    );
    // One file closed frees its share.
    let h = handles.remove(1);
    let (r, ()) = tokio::join!(h.close(&c), answer_close(&mut peer));
    r.unwrap();
    let (r, ()) = tokio::join!(smb.stat(b"/s6/f", true, &c), async {
        let gone = peer.recv_one().await;
        assert_eq!((gone.command(), gone.header.tree_id), (Command::TreeDisconnect, 22));
        peer.send(&[fake::response(&gone, NtStatus::SUCCESS, &four(), 1)], false).await;
        tree_connect(&mut peer, 25).await;
        stat_chain(&mut peer, 0x20, 5).await;
    });
    r.unwrap();
}

#[tokio::test]
async fn refused_shares() {
    let (mut smb, mut peer) = signed(&[], 1 << 20).await;
    let c = CancelToken::new();
    let (r, ()) =
        tokio::join!(smb.stat(b"/nope/x", true, &c), tree_refused(&mut peer, NtStatus::BAD_NETWORK_NAME));
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    assert!(e.message.starts_with("Sign-in failed: share not found"), "{e:?}");
    let (r, ()) =
        tokio::join!(smb.stat(b"/secret/x", true, &c), tree_refused(&mut peer, NtStatus::ACCESS_DENIED));
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy);
    assert!(e.message.contains(crate::error::SHARE_REFUSED), "{e:?}");
    // XM-2: a share that does not exist cannot be made; the share root
    // exists.
    let (r, ()) =
        tokio::join!(smb.make_dir(b"/nope", false, &c), tree_refused(&mut peer, NtStatus::BAD_NETWORK_NAME));
    assert_eq!(r, Err(Status::permission_denied("create folder: the server root holds only the shares")));
    let (r, _) = tokio::join!(smb.make_dir(b"/data", true, &c), tree_connect(&mut peer, 30));
    assert_eq!(r.unwrap_err().message, "create folder: the share root exists");
    assert_eq!(smb.make_dir(b"/data", false, &c).await, Ok(()));
    let share_denied = Status::permission_denied("remove folder: a share cannot be removed or renamed");
    assert_eq!(smb.remove_dir(b"/data", &c).await, Err(share_denied));
    assert_eq!(smb.remove_file(b"/data", &c).await.unwrap_err().message, "remove: a folder");
    // Rename between shares.
    let (r, _) = tokio::join!(
        smb.rename(b"/data/a", b"/other/b", RenameMode::NoReplace, &c),
        tree_connect(&mut peer, 31)
    );
    assert_eq!(r, Err(Status::unsupported("rename: SMB cannot move between shares")));
}

#[tokio::test]
async fn the_root_lists_saved_and_found_shares() {
    let options = [("shares", s("b, A")), ("show_admin_shares", s("false"))];
    let (mut smb, mut peer) = signed(&options, 1 << 20).await;
    let c = CancelToken::new();
    let found = [
        (Some("a"), 0, Some("x")),
        (Some("c"), 0, None),
        (Some("C$"), 0x8000_0000, None),
        (Some("ipc$"), 3, None),
    ];
    let reply = rpc::tests::fragments(&rpc::tests::enum_stub(&found, 0), 1000);
    let mut sink = Names::default();
    let options = ListOptions { batch_size: 2, ..ListOptions::default() };
    let (r, ()) =
        tokio::join!(smb.list(b"/", options, &mut sink, &c), rpc::tests::serve(&mut peer, &reply, 1000));
    r.unwrap();
    assert_eq!(sink.batches, [vec!["b", "A"], vec!["c"]]);
    // Stopped by the sink.
    let mut sink = Names { stop_after: Some(1), ..Names::default() };
    let (r, ()) =
        tokio::join!(smb.list(b"/", options, &mut sink, &c), rpc::tests::serve(&mut peer, &reply, 1000));
    let e = r.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::Canceled, "The listing was stopped"));
    // Admin shares when asked for; without enumeration only the saved
    // ones.
    let options = [("show_admin_shares", s("true"))];
    let (mut smb, mut peer) = signed(&options, 1 << 20).await;
    let mut sink = Names::default();
    let (r, ()) = tokio::join!(
        smb.list(b"/", ListOptions::default(), &mut sink, &c),
        rpc::tests::serve(&mut peer, &reply, 1000)
    );
    r.unwrap();
    assert_eq!(sink.batches, [vec!["a", "c", "C$"]]);
    let (mut smb, _peer) = signed(&[("shares", s("x")), ("share_enumeration", s("0"))], 1 << 20).await;
    let mut sink = Names::default();
    smb.list(b"/", ListOptions::default(), &mut sink, &c).await.unwrap();
    assert_eq!(sink.batches, [vec!["x"]]);
    // Enumeration that fails fails the listing.
    let (mut smb, mut peer) = signed(&[], 1 << 20).await;
    let mut sink = Names::default();
    let (r, _) = tokio::join!(
        smb.list(b"/", ListOptions::default(), &mut sink, &c),
        create(&mut peer, NtStatus::ACCESS_DENIED, 0, 0)
    );
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::PermissionDenied);
    assert!(e.message.starts_with("Cannot list the shares: "), "{e:?}");
}

#[tokio::test]
async fn download_reads_ahead_in_chunks_and_closes() {
    let (mut smb, mut peer) = signed(&share_mode(), 1000).await;
    let c = CancelToken::new();
    let mut sink = Collected::default();
    let mut progress = Moves::default();
    let (r, ()) = tokio::join!(smb.download(b"/f", 0, None, &mut sink, &mut progress, &c), async {
        let req = create(&mut peer, NtStatus::SUCCESS, 0x20, 2500).await;
        let (access, disposition, options) = create_of(&req);
        assert_eq!((access, disposition, options), (0x0010_0081, 1, 0x40));
        assert_eq!(serve_reads(&mut peer, 2500, 3).await, [(0, 1000), (1000, 1000), (2000, 500)]);
        answer_close(&mut peer).await;
    });
    r.unwrap();
    assert_eq!(sink.0, content(0, 2500));
    assert_eq!(progress.updates, [(1000, Some(2500)), (2000, Some(2500)), (2500, Some(2500))]);
    // A range.
    let mut sink = Collected::default();
    let mut progress = Moves::default();
    let (r, ()) = tokio::join!(smb.download(b"/f", 500, Some(700), &mut sink, &mut progress, &c), async {
        create(&mut peer, NtStatus::SUCCESS, 0x20, 2500).await;
        assert_eq!(serve_reads(&mut peer, 2500, 1).await, [(500, 700)]);
        answer_close(&mut peer).await;
    });
    r.unwrap();
    assert_eq!(sink.0, content(500, 1200));
    assert_eq!(progress.updates, [(700, Some(700))]);
    // Stopped by the progress: the file is closed without waiting.
    let mut progress = Moves { cancel_after: Some(0), ..Moves::default() };
    let mut sink = Collected::default();
    let (r, ()) = tokio::join!(smb.download(b"/f", 0, None, &mut sink, &mut progress, &c), async {
        create(&mut peer, NtStatus::SUCCESS, 0x20, 2500).await;
        let close = peer.recv_one().await;
        assert_eq!(close.command(), Command::Close);
    });
    assert_eq!(r.unwrap_err().name, ErrorName::Canceled);
    // A folder.
    let (r, _) =
        tokio::join!(smb.open_read(b"/d", &c), create(&mut peer, NtStatus::FILE_IS_A_DIRECTORY, 0, 0));
    let e = r.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::IsADirectory, "open: a folder"));
}

#[tokio::test]
async fn upload_writes_commits_and_sets_the_time() {
    let (mut smb, mut peer) = signed(&share_mode(), 1000).await;
    let c = CancelToken::new();
    let data = content(0, 2500);
    let mut source = Bytes { data: data.clone(), at: 0, fail: false };
    let mut progress = Moves::default();
    let options = WriteOptions { mtime_ms: Some(MS), ..WriteOptions::default() };
    let (r, ()) = tokio::join!(smb.upload(b"/new", &options, &mut source, &mut progress, &c), async {
        let req = create(&mut peer, NtStatus::SUCCESS, 0x20, 0).await;
        assert_eq!(create_of(&req), (0x0010_0082, 2, 0x40));
        assert_eq!(create_name(&req), utf16("new"));
        let mut writes = Vec::new();
        for _ in 0..3 {
            writes.push(peer.recv_one().await);
        }
        let mut got = Vec::new();
        for w in &writes {
            assert_eq!(w.command(), Command::Write);
            let b = w.body();
            let len = usize::try_from(le32(&b[4..8])).unwrap();
            assert_eq!(le64(&b[8..16]), u64::try_from(got.len()).unwrap());
            got.extend_from_slice(&b[48..][..len]);
            peer.send(&[fake::response(w, NtStatus::SUCCESS, &write_body(len), 1)], false).await;
        }
        assert_eq!(got, content(0, 2500));
        let flush = peer.recv_one().await;
        assert_eq!(flush.command(), Command::Flush);
        peer.send(&[fake::response(&flush, NtStatus::SUCCESS, &four(), 1)], false).await;
        answer_close(&mut peer).await;
        let reqs = peer.recv().await;
        assert_eq!(
            reqs.iter().map(Req::command).collect::<Vec<_>>(),
            [Command::Create, Command::SetInfo, Command::Close]
        );
        assert_eq!(le64(&reqs[1].body()[32..][16..24]), FT);
        let msgs = vec![
            fake::response(&reqs[0], NtStatus::SUCCESS, &created_body(0x20, 2500, FID), 1),
            fake::response(&reqs[1], NtStatus::SUCCESS, &[2, 0], 1),
            fake::response(&reqs[2], NtStatus::SUCCESS, &close_body(), 1),
        ];
        peer.send(&fake::chain(msgs), false).await;
    });
    r.unwrap();
    assert_eq!(progress.updates, [(1000, Some(2500)), (2000, Some(2500)), (2500, Some(2500))]);
    // The local side fails: the file is closed without a flush.
    let mut source = Bytes { data: data.clone(), at: 0, fail: true };
    let mut progress = Moves::default();
    let truncate = WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() };
    let (r, ()) = tokio::join!(smb.upload(b"/new", &truncate, &mut source, &mut progress, &c), async {
        let req = create(&mut peer, NtStatus::SUCCESS, 0x20, 0).await;
        assert_eq!(create_of(&req).1, 5);
        let write = peer.recv_one().await;
        assert_eq!(write.command(), Command::Write);
        let next = peer.recv_one().await;
        assert_eq!((next.command(), next.header.message_id), (Command::Cancel, write.header.message_id));
        let close = peer.recv_one().await;
        assert_eq!(close.command(), Command::Close);
    });
    assert_eq!(r.unwrap_err().message, "the local file went");
    // Stopped by the progress.
    let mut source = Bytes { data, at: 0, fail: false };
    let mut progress = Moves { cancel_after: Some(1), ..Moves::default() };
    let (r, ()) = tokio::join!(smb.upload(b"/new", &truncate, &mut source, &mut progress, &c), async {
        create(&mut peer, NtStatus::SUCCESS, 0x20, 0).await;
        let write = peer.recv_one().await;
        assert_eq!(write.command(), Command::Write);
        assert_eq!(peer.recv_one().await.command(), Command::Cancel);
        assert_eq!(peer.recv_one().await.command(), Command::Close);
    });
    assert_eq!(r.unwrap_err().name, ErrorName::Canceled);
}

#[tokio::test]
async fn open_write_refusals() {
    let (mut smb, mut peer) = signed(&share_mode(), 1000).await;
    let c = CancelToken::new();
    let new = WriteOptions::default();
    // A folder of that name.
    let (r, ()) = tokio::join!(smb.open_write(b"/d", &new, &c), async {
        create(&mut peer, NtStatus::OBJECT_NAME_COLLISION, 0, 0).await;
        stat_chain(&mut peer, 0x10, 0).await;
    });
    let e = r.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::IsADirectory, "open: a folder"));
    // A file of that name.
    let (r, ()) = tokio::join!(smb.open_write(b"/f", &new, &c), async {
        create(&mut peer, NtStatus::OBJECT_NAME_COLLISION, 0, 0).await;
        stat_chain(&mut peer, 0x20, 3).await;
    });
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    assert!(e.message.starts_with("open: "), "{e:?}");
    // Resume where the file does not end.
    let resume =
        WriteOptions { disposition: Disposition::Resume, resume_offset: 5, ..WriteOptions::default() };
    let (r, ()) = tokio::join!(smb.open_write(b"/f", &resume, &c), async {
        let req = create(&mut peer, NtStatus::SUCCESS, 0x20, 10).await;
        assert_eq!(create_of(&req), (0x0010_0083, 1, 0x40));
        assert_eq!(peer.recv_one().await.command(), Command::Close);
    });
    let e = r.unwrap_err();
    assert_eq!(
        (e.name, e.message.as_str()),
        (ErrorName::ProtocolError, "Cannot resume at 5: the file has 10 bytes")
    );
    // Where it ends.
    let (r, _) =
        tokio::join!(smb.open_write(b"/f", &resume, &c), create(&mut peer, NtStatus::SUCCESS, 0x20, 5));
    let w = r.unwrap();
    assert_eq!(w.position(), 5);
    w.abort().await;
    assert_eq!(peer.recv_one().await.command(), Command::Close);
}

#[tokio::test]
async fn namespace_calls_reach_the_share() {
    let (mut smb, mut peer) = signed(&share_mode(), 1000).await;
    let c = CancelToken::new();
    let (r, ()) = tokio::join!(smb.stat(b"/a/b", false, &c), async {
        assert_eq!(stat_chain(&mut peer, 0x20, 7).await, (9, utf16(r"a\b")));
    });
    assert_eq!(r.unwrap().size, Some(7));
    // The share root of share mode has no name.
    let (r, _) = tokio::join!(smb.stat(b"/", false, &c), stat_chain(&mut peer, 0x10, 0));
    assert_eq!(r.unwrap().name, b"");
    // An empty change set checks that the entry exists.
    let none = Attributes::default();
    let (r, _) = tokio::join!(smb.set_attributes(b"/a", &none, &c), stat_chain(&mut peer, 0x20, 0));
    r.unwrap();
    let changes = Attributes { atime_ms: Some(MS), ..Attributes::default() };
    let (r, ()) = tokio::join!(smb.set_attributes(b"/a", &changes, &c), async {
        let reqs = peer.recv().await;
        let info = &reqs[1].body()[32..];
        assert_eq!((le64(&info[8..16]), le64(&info[16..24])), (FT, 0));
        let msgs = vec![
            fake::response(&reqs[0], NtStatus::SUCCESS, &created_body(0x20, 0, FID), 1),
            fake::response(&reqs[1], NtStatus::SUCCESS, &[2, 0], 1),
            fake::response(&reqs[2], NtStatus::SUCCESS, &close_body(), 1),
        ];
        peer.send(&fake::chain(msgs), false).await;
    });
    r.unwrap();
    // A failure names the call.
    let (r, ()) = tokio::join!(smb.remove_file(b"/gone", &c), async {
        let reqs = peer.recv().await;
        let msgs: Vec<Vec<u8>> =
            reqs.iter().map(|r| fake::error(r, NtStatus::OBJECT_NAME_NOT_FOUND, 1)).collect();
        peer.send(&fake::chain(msgs), false).await;
    });
    let e = r.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    assert!(e.message.starts_with("remove: "), "{e:?}");
    // ECHO.
    let (r, ()) = tokio::join!(smb.keep_alive(&c), async {
        let echo = peer.recv_one().await;
        assert_eq!(echo.command(), Command::Echo);
        peer.send(&[fake::response(&echo, NtStatus::SUCCESS, &four(), 1)], false).await;
    });
    r.unwrap();
    // Disconnect: LOGOFF, then nothing works; open handles are lost.
    let (r, _) = tokio::join!(smb.open_read(b"/f", &c), create(&mut peer, NtStatus::SUCCESS, 0x20, 5));
    let mut h = r.unwrap();
    smb.disconnect().await;
    assert_eq!(peer.recv_one().await.command(), Command::Logoff);
    assert_eq!(smb.stat(b"/a", false, &c).await.unwrap_err().message, "Not signed in");
    assert_eq!(smb.capabilities(), Capabilities::default());
    let e = h.read(0, &mut [0; 4], &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
}
