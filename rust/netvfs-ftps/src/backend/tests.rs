// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(
    clippy::arithmetic_side_effects,
    clippy::items_after_statements,
    clippy::many_single_char_names,
    reason = "tests"
)]
use super::*;
use crate::fake::{CA, Cert, Fake, LEAF, MTIME_MS, Node, PASSWORD, SELF, USER};
use netvfs_vfs::{EntryFlags, IdentityKind, Value};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;

fn anchors() -> Anchors {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(CA.to_vec())).unwrap();
    Anchors::Custom(Arc::new(store))
}

fn spki(cert: &[u8]) -> Vec<u8> {
    // The SPKI is the one P-256 key SEQUENCE inside the certificate.
    let at = cert.windows(4).position(|w| w == [0x30, 0x59, 0x30, 0x13]).unwrap();
    cert[at..at + 91].to_vec()
}

fn pin(cert: &[u8]) -> String {
    format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(&spki(cert)))
}

fn params(fake: &Fake, options: &[(&str, &str)]) -> Params {
    let mut p = Params {
        provider: "ftps".into(),
        host: "localhost".into(),
        port: i32::from(fake.addr.port()),
        username: USER.into(),
        // A reply that never comes fails the test in seconds.
        request_timeout_ms: 5000,
        ..Params::default()
    };
    for (k, v) in options {
        p.options.insert((*k).into(), Value::Str((*v).into()));
    }
    p
}

fn creds(user: &str, secret: &str) -> Credentials {
    Credentials {
        user: user.into(),
        secret: Zeroizing::new(secret.as_bytes().to_vec()),
        domain: String::new(),
    }
}

async fn signed_in(fake: &Fake) -> Ftps {
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    assert_eq!(f.connect(&params(fake, &[]), &c).await.unwrap(), None);
    f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap();
    fake.with(|s| s.seen.clear());
    f
}

#[derive(Default)]
struct Collect(Vec<Entry>, usize);

impl ListSink for Collect {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        self.1 += 1;
        true
    }
}

struct Data(Vec<u8>, usize, usize);

impl Source for Data {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        self.2 = self.2.max(buf.len());
        let n = buf.len().min(self.0.len() - self.1);
        buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
        self.1 += n;
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

#[derive(Default)]
struct Out(Vec<u8>);

impl Sink for Out {
    fn write(&mut self, data: &[u8]) -> Result<(), Status> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

/// Progress that cancels once `after` bytes moved.
struct Moves {
    after: Option<u64>,
    last: (u64, Option<u64>),
}

impl Moves {
    const fn quiet() -> Self {
        Self { after: None, last: (0, None) }
    }
}

impl Progress for Moves {
    fn update(&mut self, done: u64, total: Option<u64>) {
        self.last = (done, total);
    }
    fn canceled(&mut self) -> bool {
        self.after.is_some_and(|a| self.last.0 >= a)
    }
}

fn names(entries: &[Entry]) -> Vec<String> {
    let mut n: Vec<String> = entries.iter().map(|e| String::from_utf8_lossy(&e.name).into_owned()).collect();
    n.sort();
    n
}

fn file(data: &[u8]) -> Node {
    Node::File(data.to_vec())
}

fn opts(disposition: Disposition) -> WriteOptions {
    WriteOptions { disposition, ..WriteOptions::default() }
}

// ---- connect and sign in

#[tokio::test]
async fn a_self_signed_server_reports_its_key_and_hears_no_credentials() {
    let fake = Fake::start(Cert::SelfSigned).await;
    let mut f = Ftps::with_anchors(anchors());
    let id = f.connect(&params(&fake, &[]), &CancelToken::new()).await.unwrap().unwrap();
    assert_eq!((id.kind, id.algorithm.as_str()), (IdentityKind::Tls, "tls-spki-sha256"));
    assert_eq!(id.public_key, spki(SELF));
    assert_eq!(fake.verbs(), ["AUTH"], "connect only shakes hands");
    assert_eq!(f.capabilities(), Capabilities::default());
}

#[tokio::test]
async fn a_trusted_server_needs_no_pin_but_a_pinned_account_sees_the_key() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    assert_eq!(f.connect(&params(&fake, &[]), &c).await.unwrap(), None);
    let id = f.connect(&params(&fake, &[("host_key", &pin(LEAF))]), &c).await.unwrap().unwrap();
    assert_eq!(id.public_key, spki(LEAF));
    f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap();
    let mut system = Ftps::new();
    assert!(system.connect(&params(&fake, &[]), &c).await.unwrap().is_some());
}

#[tokio::test]
async fn a_key_other_than_the_pin_gets_no_credentials() {
    let fake = Fake::start(Cert::SelfSigned).await;
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    for wrong in [pin(LEAF), "tls-spki-sha256 ***".to_owned()] {
        f.connect(&params(&fake, &[("host_key", &wrong)]), &c).await.unwrap().unwrap();
        let e = f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap_err();
        assert_eq!(e.name, ErrorName::ServerIdentityChanged);
    }
    assert!(!fake.verbs().contains(&"USER".to_owned()));
    f.connect(&params(&fake, &[("host_key", &pin(SELF))]), &c).await.unwrap();
    f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap();
}

#[tokio::test]
async fn sign_in_protects_data_and_asks_for_utf8() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    f.connect(&params(&fake, &[]), &c).await.unwrap();
    // The account's user name when the credentials name none.
    f.authenticate(&creds("", PASSWORD), None, &c).await.unwrap();
    let seen = fake.with(|s| s.seen.clone());
    let lines: Vec<&[u8]> = seen.iter().map(Vec::as_slice).collect();
    assert_eq!(
        lines,
        [
            &b"AUTH TLS"[..],
            b"USER alice",
            b"PASS ***",
            b"PBSZ 0",
            b"PROT P",
            b"TYPE I",
            b"FEAT",
            b"OPTS UTF8 ON"
        ]
    );
    fake.with(|s| s.features.retain(|f| *f != "UTF8"));
    f.connect(&params(&fake, &[]), &c).await.unwrap();
    f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap();
    assert_eq!(fake.verbs().last().unwrap(), "FEAT");
}

#[tokio::test]
async fn sign_in_failures() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    let mut fail = async |user: &str, secret: &str| {
        f.connect(&params(&fake, &[]), &c).await.unwrap();
        let e = f.authenticate(&creds(user, secret), None, &c).await.unwrap_err();
        assert_eq!(f.stat(b"/", false, &c).await.unwrap_err().message, "Not signed in");
        e
    };
    assert_eq!(fail(USER, "wrong").await.name, ErrorName::AuthFailed);
    assert_eq!(fail("bob", PASSWORD).await.name, ErrorName::AuthFailed);
    let mut p = params(&fake, &[]);
    p.username.clear();
    f.connect(&p, &c).await.unwrap();
    let e = f.authenticate(&creds("", PASSWORD), None, &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::AuthFailed, "FTP needs a user name"));
    let mut fail = async |user: &str, secret: &str| {
        f.connect(&params(&fake, &[]), &c).await.unwrap();
        f.authenticate(&creds(user, secret), None, &c).await.unwrap_err()
    };
    assert_eq!(fail(USER, "a\r\nDELE /x").await.message, "Unusable password");
    assert_eq!(fail("a\r\nDELE /x", PASSWORD).await.name, ErrorName::InvalidName);
    fake.with(|s| s.prot_code = 534);
    assert_eq!(fail(USER, PASSWORD).await.name, ErrorName::SecurityPolicy);
    fake.with(|s| {
        s.prot_code = 200;
        s.features = vec!["EPSV", "UTF8"];
    });
    assert_eq!(fail(USER, PASSWORD).await.name, ErrorName::Unsupported);
    assert!(!fake.verbs().contains(&"DELE".to_owned()));
}

#[tokio::test]
async fn a_server_without_tls_is_refused() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.with(|s| s.auth_code = 500);
    let mut f = Ftps::with_anchors(anchors());
    let e = f.connect(&params(&fake, &[]), &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy);
    assert_eq!(fake.verbs(), ["AUTH"]);
}

#[tokio::test]
async fn authenticate_needs_a_fresh_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    assert_eq!(f.authenticate(&creds(USER, PASSWORD), None, &c).await.unwrap_err().name, ErrorName::Internal);
    f.stat(b"/", false, &c).await.unwrap();
    let mut idle = Ftps::new();
    assert_eq!(idle.authenticate(&creds("a", "b"), None, &c).await.unwrap_err().name, ErrorName::Internal);
}

#[test]
fn settings_from_params() {
    let p = Params {
        host: "[::1]".into(),
        port: 0,
        username: "u".into(),
        connect_timeout_ms: 5,
        request_timeout_ms: -1,
        ..Params::default()
    };
    let s = Settings::of(&p).unwrap();
    assert_eq!(
        s.target,
        Target {
            host: "::1".into(),
            port: DEFAULT_PORT,
            connect_timeout: Duration::from_millis(5),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    );
    assert_eq!((s.username.as_str(), s.pin), ("u", None));
    let mut p = Params { host: "h".into(), port: 990, ..Params::default() };
    p.options.insert("host_key".into(), Value::Str("tls-spki-sha256 x".into()));
    let s = Settings::of(&p).unwrap();
    assert_eq!(
        (s.target.port, s.target.connect_timeout, s.pin.as_deref()),
        (990, DEFAULT_CONNECT_TIMEOUT, Some("tls-spki-sha256 x"))
    );
    p.options.insert("host_key".into(), Value::Str(String::new()));
    assert_eq!(Settings::of(&p).unwrap().pin, None);
    for bad in [
        Params { host: String::new(), ..Params::default() },
        Params { host: "a@b".into(), ..Params::default() },
        Params { host: "a/b".into(), ..Params::default() },
        Params { host: "h".into(), port: 65_536, ..Params::default() },
    ] {
        assert_eq!(Settings::of(&bad).unwrap_err().name, ErrorName::Internal);
    }
}

// ---- operations

#[tokio::test]
async fn stat_files_folders_and_missing_ones() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/d", Node::Dir);
    fake.put("/d/f.txt", file(b"hello"));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let e = f.stat(b"/d/f.txt", true, &c).await.unwrap();
    assert_eq!(
        (e.name.as_slice(), e.kind, e.size, e.mtime_ms, e.mode),
        (&b"f.txt"[..], EntryType::File, Some(5), Some(MTIME_MS), Some(0o644))
    );
    let d = f.stat(b"/d/", false, &c).await.unwrap();
    assert_eq!((d.kind, d.size), (EntryType::Directory, None));
    assert_eq!(f.stat(b"/", false, &c).await.unwrap().kind, EntryType::Directory);
    assert_eq!(f.stat(b"/nope", false, &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(f.stat(b"/a\nb", false, &c).await.unwrap_err().name, ErrorName::InvalidName);
    assert_eq!(fake.with(|s| s.seen.last().cloned()).unwrap(), b"MLST /nope");
}

#[tokio::test]
async fn list_gives_children_in_batches_and_skips_hostile_lines() {
    let fake = Fake::start(Cert::Trusted).await;
    for n in ["/a", "/b", "/c"] {
        fake.put(n, file(b"x"));
    }
    fake.put("/sub", Node::Dir);
    fake.with(|s| {
        s.extra_lines = vec![
            b"type=dir; .".to_vec(),
            b"garbage without facts".to_vec(),
            b"type=file;size=1; ".to_vec(),
            b"type=file;size=2; caf\xe9".to_vec(),
        ];
    });
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut sink = Collect::default();
    f.list(b"/", ListOptions { batch_size: 2, ..ListOptions::default() }, &mut sink, &c).await.unwrap();
    assert_eq!(names(&sink.0), ["a", "b", "c", "caf\u{fffd}", "sub"]);
    assert_eq!(sink.1, 3);
    let latin = sink.0.iter().find(|e| e.name == b"caf\xe9").unwrap();
    assert_eq!((latin.flags, latin.size), (EntryFlags::NAME_NOT_UTF8, Some(2)));
    assert_eq!(fake.with(|s| s.resumed), 1, "the data connection resumed the control session");
    fake.with(|s| s.extra_lines.clear());
    let mut empty = Collect::default();
    f.list(b"/sub", ListOptions::default(), &mut empty, &c).await.unwrap();
    assert_eq!(names(&empty.0), Vec::<String>::new());
    // A sink that stops cancels the listing.
    struct Stop;
    impl ListSink for Stop {
        fn entries(&mut self, _: &[Entry]) -> bool {
            false
        }
    }
    let e = f.list(b"/", ListOptions::default(), &mut Stop, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    let mut sink = Collect::default();
    let e = f.list(b"/nope", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    let e = f.list(b"/a", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotADirectory);
}

#[tokio::test]
async fn data_connections_must_resume_the_control_session() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    for _ in 0..3 {
        f.list(b"/", ListOptions::default(), &mut Collect::default(), &c).await.unwrap();
    }
    assert_eq!(fake.with(|s| s.resumed), 3);
}

#[tokio::test]
async fn make_dir_exclusive_or_not() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    f.make_dir(b"/d", true, &c).await.unwrap();
    assert_eq!(fake.get("/d"), Some(Node::Dir));
    f.make_dir(b"/d", false, &c).await.unwrap();
    assert_eq!(f.make_dir(b"/d", true, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    assert_eq!(f.make_dir(b"/f", false, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    f.make_dir(b"/", false, &c).await.unwrap();
    assert_eq!(f.make_dir(b"/", true, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    assert_eq!(f.make_dir(b"/no/d", false, &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(f.make_dir(b"/f/d", false, &c).await.unwrap_err().name, ErrorName::NotADirectory);
}

#[tokio::test]
async fn remove_files_and_empty_folders_only() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    fake.put("/d", Node::Dir);
    fake.put("/d/g", file(b"y"));
    fake.put("/e", Node::Dir);
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    assert_eq!(f.remove_file(b"/d", &c).await.unwrap_err().name, ErrorName::IsADirectory);
    assert_eq!(f.remove_dir(b"/f", &c).await.unwrap_err().name, ErrorName::NotADirectory);
    assert_eq!(f.remove_dir(b"/d", &c).await.unwrap_err().name, ErrorName::DirectoryNotEmpty);
    assert_eq!(f.remove_dir(b"/", &c).await.unwrap_err().name, ErrorName::PermissionDenied);
    assert_eq!(f.remove_file(b"/nope", &c).await.unwrap_err().name, ErrorName::NotFound);
    f.remove_file(b"/f", &c).await.unwrap();
    f.remove_dir(b"/e", &c).await.unwrap();
    assert_eq!((fake.get("/f"), fake.get("/e")), (None, None));
    assert_eq!(fake.get("/d"), Some(Node::Dir));
}

#[tokio::test]
async fn rename_modes() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/a", file(b"a"));
    fake.put("/b", file(b"b"));
    fake.put("/d", Node::Dir);
    fake.put("/d/x", file(b"x"));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let e = f.rename(b"/a", b"/b", RenameMode::NoReplace, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    assert_eq!(
        f.rename(b"/a", b"/d", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    assert_eq!(
        f.rename(b"/d", b"/a", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    f.rename(b"/a", b"/a", RenameMode::NoReplace, &c).await.unwrap();
    f.rename(b"/a", b"/b", RenameMode::Replace, &c).await.unwrap();
    assert_eq!((fake.get("/a"), fake.get("/b")), (None, Some(file(b"a"))));
    f.rename(b"/d", b"/e", RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!(fake.get("/e/x"), Some(file(b"x")));
    assert_eq!(
        f.rename(b"/nope", b"/z", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::NotFound
    );
    let e = f.rename(b"/b", b"/missing/z", RenameMode::Replace, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    assert_eq!(fake.get("/b"), Some(file(b"a")));
}

#[tokio::test]
async fn refusals_are_explained_by_their_parents() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/locked", Node::Dir);
    fake.put("/f", file(b"x"));
    fake.with(|s| s.forbidden = Some(b"/locked/n".to_vec()));
    let mut ftps = signed_in(&fake).await;
    let c = CancelToken::new();
    let e = ftps.make_dir(b"/locked/n", false, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::PermissionDenied);
    assert_eq!(e.detail, "550 Permission denied");
    let (o, mut p) = (opts(Disposition::Truncate), Moves::quiet());
    let e = ftps.upload(b"/f/n", &o, &mut Data(b"x".to_vec(), 0, 0), &mut p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotADirectory);
    let e = ftps.upload(b"/no/n", &o, &mut Data(b"x".to_vec(), 0, 0), &mut p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    // The connection stays usable.
    ftps.stat(b"/f", false, &c).await.unwrap();
}

#[tokio::test]
async fn download_whole_and_ranges() {
    let fake = Fake::start(Cert::Trusted).await;
    let body: Vec<u8> = (0..=255u8).cycle().take(600_000).collect();
    fake.put("/f", Node::File(body.clone()));
    fake.put("/d", Node::Dir);
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut get = async |offset: u64, length: Option<u64>| {
        let mut out = Out::default();
        let mut p = Moves::quiet();
        f.download(b"/f", offset, length, &mut out, &mut p, &c).await.unwrap();
        (out.0, p.last)
    };
    let (all, last) = get(0, None).await;
    assert!(all == body);
    assert_eq!(last, (600_000, Some(600_000)));
    let (tail, last) = get(599_990, None).await;
    assert_eq!((tail.as_slice(), last), (&body[599_990..], (10, Some(10))));
    let (mid, last) = get(1000, Some(300_000)).await;
    assert!(mid == body[1000..301_000]);
    assert_eq!(last, (300_000, Some(300_000)));
    assert_eq!(get(600_000, None).await.0, b"");
    assert_eq!(get(5, Some(0)).await.0, b"");
    assert_eq!(get(599_999, Some(10)).await.0, &body[599_999..]);
    assert!(fake.with(|s| s.seen.iter().any(|l| l == b"REST 1000")));
    // The connection is in step after a cut-off read.
    f.stat(b"/f", false, &c).await.unwrap();
    let mut out = Out::default();
    let e = f.download(b"/d", 0, None, &mut out, &mut Moves::quiet(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::IsADirectory);
}

/// Progress that cancels the token once a byte moved: the call's future is dropped mid-transfer.
struct Drop(CancelToken);

impl Progress for Drop {
    fn update(&mut self, done: u64, _: Option<u64>) {
        if done > 0 {
            self.0.cancel();
        }
    }
    fn canceled(&mut self) -> bool {
        false
    }
}

#[tokio::test]
async fn canceled_transfers_leave_the_connection_usable() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/f", Node::File(vec![7; 8 << 20]));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut p = Moves { after: Some(1), last: (0, None) };
    let e = f.download(b"/f", 0, None, &mut Out::default(), &mut p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(f.stat(b"/f", false, &c).await.unwrap().size, Some(8 << 20));
    for _ in 0..2 {
        let token = CancelToken::new();
        let e = f.download(b"/f", 0, None, &mut Out::default(), &mut Drop(token.clone()), &token).await;
        assert_eq!(e.unwrap_err().name, ErrorName::Canceled);
        let token = CancelToken::new();
        let o = opts(Disposition::Truncate);
        let e =
            f.upload(b"/u", &o, &mut Data(vec![1; 8 << 20], 0, 0), &mut Drop(token.clone()), &token).await;
        assert_eq!(e.unwrap_err().name, ErrorName::Canceled);
    }
    f.keep_alive(&c).await.unwrap();
    assert_eq!(fake.with(|s| s.connections), 1);
    // Downloads only: a stopped upload ends with a TLS close.
    assert_eq!(fake.verbs().iter().filter(|v| *v == "ABOR").count(), 3);
}

#[tokio::test]
async fn stray_replies_after_abort_are_skipped() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/f", Node::File(vec![7; 8 << 20]));
    fake.with(|s| s.abort_extra = Some("426 Transfer aborted"));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut out = Out::default();
    f.download(b"/f", 0, Some(1000), &mut out, &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(out.0.len(), 1000);
    let mut out = Out::default();
    f.download(b"/f", 0, Some(2000), &mut out, &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(out.0.len(), 2000);
    assert_eq!(fake.with(|s| s.connections), 1);
}

#[tokio::test]
async fn uploads() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/old", file(b"old"));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let body: Vec<u8> = (0..=255u8).cycle().take(CHUNK + 5).collect();
    let mut p = Moves::quiet();
    f.upload(b"/new", &opts(Disposition::CreateNew), &mut Data(body.clone(), 0, 0), &mut p, &c)
        .await
        .unwrap();
    assert!(fake.get("/new") == Some(Node::File(body.clone())));
    assert_eq!(p.last, (CHUNK as u64 + 5, Some(CHUNK as u64 + 5)));
    let e =
        f.upload(b"/old", &opts(Disposition::CreateNew), &mut Data(b"x".to_vec(), 0, 0), &mut p, &c).await;
    assert_eq!(e.unwrap_err().name, ErrorName::AlreadyExists);
    f.upload(b"/old", &opts(Disposition::Truncate), &mut Data(b"new".to_vec(), 0, 0), &mut p, &c)
        .await
        .unwrap();
    assert_eq!(fake.get("/old"), Some(file(b"new")));
    f.upload(b"/empty", &opts(Disposition::Truncate), &mut Data(Vec::new(), 0, 0), &mut p, &c).await.unwrap();
    assert_eq!(fake.get("/empty"), Some(file(b"")));
    let e = f.upload(b"/old", &opts(Disposition::Resume), &mut Data(b"x".to_vec(), 0, 0), &mut p, &c).await;
    assert_eq!(e.unwrap_err().name, ErrorName::Unsupported);
    assert_eq!(fake.get("/old"), Some(file(b"new")));
    let mut stop = Moves { after: Some(1), last: (0, None) };
    let e = f.upload(b"/cut", &opts(Disposition::Truncate), &mut Data(body, 0, 0), &mut stop, &c).await;
    assert_eq!(e.unwrap_err().name, ErrorName::Canceled);
    assert_eq!(f.stat(b"/new", false, &c).await.unwrap().size, Some(CHUNK as u64 + 5));
}

#[tokio::test]
async fn keep_alive_disconnect_and_cancel() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    f.keep_alive(&c).await.unwrap();
    let canceled = CancelToken::new();
    canceled.cancel();
    assert_eq!(f.stat(b"/", false, &canceled).await.unwrap_err().name, ErrorName::Canceled);
    f.disconnect().await;
    assert_eq!(fake.verbs(), ["NOOP", "QUIT"]);
    assert_eq!(f.keep_alive(&c).await.unwrap_err().name, ErrorName::Internal);
    assert_eq!(fake.with(|s| s.connections), 1);
}

#[tokio::test]
async fn unreachable_servers() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut p = params(&fake, &[]);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    p.port = i32::from(closed.local_addr().unwrap().port());
    drop(closed);
    let mut f = Ftps::with_anchors(anchors());
    let e = f.connect(&p, &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NetworkUnreachable);
}

#[tokio::test]
async fn odd_sign_ins() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.with(|s| s.greeting_wait = true);
    let mut f = Ftps::with_anchors(anchors());
    let c = CancelToken::new();
    f.connect(&params(&fake, &[]), &c).await.unwrap();
    // No password asked.
    f.authenticate(&creds("guest", ""), None, &c).await.unwrap();
    assert!(!fake.verbs().contains(&"PASS".to_owned()));
    f.stat(b"/", false, &c).await.unwrap();
    for user in ["acct", "pacct"] {
        f.connect(&params(&fake, &[]), &c).await.unwrap();
        let e = f.authenticate(&creds(user, PASSWORD), None, &c).await.unwrap_err();
        assert_eq!(
            (e.name, e.message.as_str()),
            (ErrorName::Unsupported, "The server asks for an account (ACCT)")
        );
    }
}

#[tokio::test]
async fn refusals_other_than_missing_entries_are_errors() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/a", file(b"a"));
    fake.put("/d", Node::Dir);
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    fake.with(|s| s.refuse = Some(("MLST", b"/b".to_vec(), "500 Syntax error")));
    let e = f.rename(b"/a", b"/b", RenameMode::Replace, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Unsupported);
    assert_eq!(fake.get("/a"), Some(file(b"a")));
    let mut sink = Collect::default();
    fake.with(|s| s.refuse = Some(("MLSD", b"/a".to_vec(), "425 Cannot open data connection")));
    let e = f.list(b"/a", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
    fake.with(|s| s.refuse = Some(("MLSD", b"/d".to_vec(), "550 No access")));
    let e = f.list(b"/d", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::PermissionDenied);
    fake.with(|s| s.refuse = Some(("MLSD", b"/d".to_vec(), "501 Odd")));
    let e = f.list(b"/d", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError);
    fake.with(|s| s.refuse = Some(("MLSD", b"/gone".to_vec(), "501 No such directory.")));
    let e = f.list(b"/gone", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    let no_epsv = "The server does not offer extended passive mode (EPSV)";
    for (reply, name, no) in [
        ("425 EPSV: Address already in use", ErrorName::ConnectionLost, false),
        ("500 EPSV not understood", ErrorName::Unsupported, true),
        ("502 Not implemented", ErrorName::Unsupported, true),
        ("501 Odd", ErrorName::ProtocolError, false),
    ] {
        fake.with(|s| s.refuse = Some(("EPSV", b"/".to_vec(), reply)));
        let e = f.list(b"/d", ListOptions::default(), &mut sink, &c).await.unwrap_err();
        assert_eq!((e.name, e.message == no_epsv), (name, no), "{reply}");
    }
}

#[tokio::test]
async fn the_parent_is_the_path_up_to_its_last_slash() {
    let fake = Fake::start(Cert::Trusted).await;
    // "/x/c" alone, without "/x".
    fake.put("/x/c", Node::Dir);
    fake.with(|s| s.forbidden = Some(b"/x/cd".to_vec()));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let e = f.make_dir(b"/x/cd", false, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
}

#[tokio::test]
async fn uploads_read_256_kib_at_a_time() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = signed_in(&fake).await;
    let mut source = Data(vec![1; 10], 0, 0);
    let o = opts(Disposition::Truncate);
    f.upload(b"/f", &o, &mut source, &mut Moves::quiet(), &CancelToken::new()).await.unwrap();
    assert_eq!(source.2, 256 * 1024);
}

#[tokio::test]
async fn downloads_ask_only_for_what_they_need() {
    let fake = Fake::start(Cert::Trusted).await;
    let body = vec![3u8; 8 << 20];
    fake.put("/f", Node::File(body));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut get = async |offset: u64, length: Option<u64>| {
        fake.with(|s| s.seen.clear());
        let mut out = Out::default();
        let r = f.download(b"/f", offset, length, &mut out, &mut Moves::quiet(), &c).await;
        (r, out.0.len(), fake.verbs())
    };
    let (r, n, verbs) = get(8 << 20, None).await;
    assert_eq!((r, n, verbs), (Ok(()), 0, vec!["MLST".to_owned()]));
    let (r, n, verbs) = get(5, Some(0)).await;
    assert_eq!((r, n, verbs), (Ok(()), 0, vec!["MLST".to_owned()]));
    // A short read of a large file stops the transfer.
    let (r, n, verbs) = get(0, Some(1000)).await;
    assert_eq!((r, n), (Ok(()), 1000));
    assert_eq!(verbs, ["MLST", "EPSV", "RETR", "ABOR", "NOOP"]);
    let (r, _, verbs) = get(0, Some(0)).await;
    assert_eq!((r, verbs), (Ok(()), vec!["MLST".to_owned()]), "in step");
    // A whole read the server reports failed is an error.
    fake.with(|s| s.retr_end = Some("451 Local error"));
    let (r, n, _) = get(0, None).await;
    assert_eq!((r.unwrap_err().name, n), (ErrorName::ProtocolError, 8 << 20));
}

#[tokio::test]
async fn listings_are_read_up_to_32_mib() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut listing = b"type=file; a\r\n".to_vec();
    while listing.len() < 32 << 20 {
        let line = (1024).min((32 << 20) - listing.len());
        listing.extend(std::iter::repeat_n(b'x', line.saturating_sub(2)));
        listing.extend_from_slice(&b"\r\n"[..line.min(2)]);
    }
    assert_eq!(listing.len(), 32 << 20);
    fake.with(|s| s.listing = Some(listing.clone()));
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    let mut sink = Collect::default();
    f.list(b"/", ListOptions::default(), &mut sink, &c).await.unwrap();
    assert_eq!(names(&sink.0), ["a"]);
    listing.push(b'x');
    fake.with(|s| s.listing = Some(listing));
    let e = f.list(b"/", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError);
}

#[tokio::test]
async fn a_closing_server_ends_the_connection() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    fake.with(|s| s.refuse = Some(("NOOP", b"/".to_vec(), "421 Shutting down")));
    assert_eq!(f.keep_alive(&c).await.unwrap_err().name, ErrorName::ConnectionLost);
    let e = f.stat(b"/", false, &c).await.unwrap_err();
    assert_eq!((e.name, e.detail.as_str()), (ErrorName::ConnectionLost, "an earlier command did not finish"));
    f.disconnect().await;
    assert_eq!(fake.verbs(), ["NOOP"], "no QUIT on a torn connection");
}

#[tokio::test]
async fn a_fresh_session_brings_tickets_when_uploads_used_them_up() {
    let fake = Fake::start(Cert::Trusted).await;
    fake.put("/d", Node::Dir);
    let mut f = signed_in(&fake).await;
    let c = CancelToken::new();
    for i in 0..6 {
        let path = format!("/d/{i}");
        f.upload(
            path.as_bytes(),
            &opts(Disposition::Truncate),
            &mut Data(vec![b'x'], 0, 0),
            &mut Moves::quiet(),
            &c,
        )
        .await
        .unwrap();
    }
    assert!(fake.get("/d/5") == Some(file(b"x")));
    // Two tickets per sign-in, none per upload: a fresh session before the 3rd and 5th upload.
    assert_eq!(fake.with(|s| s.connections), 3);
    f.stat(b"/d", false, &c).await.unwrap();
    assert_eq!(fake.with(|s| s.connections), 3, "no data connection, no fresh session");
    let mut sink = Collect(Vec::new(), 0);
    f.list(b"/d", ListOptions::default(), &mut sink, &c).await.unwrap();
    assert_eq!(sink.0.len(), 6);
    assert_eq!(fake.with(|s| s.connections), 4);
    let mut f = signed_in(&fake).await;
    for i in 0..2 {
        let path = format!("/d/{i}");
        let mut source = Data(b"yz".to_vec(), 0, 0);
        f.upload(path.as_bytes(), &opts(Disposition::Truncate), &mut source, &mut Moves::quiet(), &c)
            .await
            .unwrap();
    }
    let mut out = Out::default();
    f.download(b"/d/1", 1, None, &mut out, &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(out.0, b"z");
    assert_eq!(fake.with(|s| s.connections), 6);
}
