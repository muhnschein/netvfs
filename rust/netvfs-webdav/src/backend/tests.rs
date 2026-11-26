// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(clippy::arithmetic_side_effects, clippy::items_after_statements, reason = "tests")]
use super::*;
use crate::fake::{CA, Cert, Fake, LEAF, MTIME_MS, Node, SELF};
use netvfs_vfs::{Disposition, IdentityKind, ReadHandle, Value};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;

const AUTH: &str = "Basic YWxpY2U6c2VjcmV0";

fn anchors() -> Anchors {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(CA.to_vec())).unwrap();
    Anchors::Custom(Arc::new(store))
}

fn spki(cert: &[u8]) -> Vec<u8> {
    webpki_spki(cert)
}

fn webpki_spki(cert: &[u8]) -> Vec<u8> {
    let at = cert.windows(4).position(|w| w == [0x30, 0x59, 0x30, 0x13]).unwrap();
    cert[at..at + 91].to_vec()
}

fn pin(cert: &[u8]) -> String {
    format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(&spki(cert)))
}

fn params(fake: &Fake, options: &[(&str, &str)]) -> Params {
    let mut p = Params {
        provider: "webdav".into(),
        host: "localhost".into(),
        port: i32::from(fake.addr.port()),
        username: "alice".into(),
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

async fn server(cert: Cert) -> Fake {
    let fake = Fake::start(cert).await;
    fake.with(|s| s.auth = Some(AUTH.to_owned()));
    fake
}

async fn signed_in(fake: &Fake, base: &str) -> Webdav {
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    assert_eq!(w.connect(&params(fake, &[("base_path", base)]), &c).await.unwrap(), None);
    w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap();
    fake.clear_seen();
    w
}

#[derive(Default)]
struct Collect(Vec<Entry>);

impl ListSink for Collect {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        true
    }
}

struct Data(Vec<u8>, usize, bool);

impl Source for Data {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        let n = buf.len().min(self.0.len() - self.1).min(100_000);
        buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
        self.1 += n;
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        self.2.then_some(self.0.len() as u64)
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

#[tokio::test]
async fn a_self_signed_server_reports_its_key_and_hears_no_credentials() {
    let fake = server(Cert::SelfSigned).await;
    let mut w = Webdav::with_anchors(anchors());
    let id = w.connect(&params(&fake, &[]), &CancelToken::new()).await.unwrap().unwrap();
    assert_eq!((id.kind, id.algorithm.as_str()), (IdentityKind::Tls, "tls-spki-sha256"));
    assert_eq!(id.public_key, spki(SELF));
    assert!(fake.seen().is_empty(), "connect sends no request");
    assert_eq!(w.capabilities(), Capabilities::default());
}

#[tokio::test]
async fn a_trusted_server_needs_no_pin_but_a_pinned_account_sees_the_key() {
    let fake = server(Cert::Trusted).await;
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    assert_eq!(w.connect(&params(&fake, &[]), &c).await.unwrap(), None);
    let id = w.connect(&params(&fake, &[("host_key", &pin(LEAF))]), &c).await.unwrap().unwrap();
    assert_eq!(id.public_key, spki(LEAF));
    w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap();
    let mut system = Webdav::new();
    assert!(system.connect(&params(&fake, &[]), &c).await.unwrap().is_some());
}

#[tokio::test]
async fn a_key_other_than_the_pin_gets_no_credentials() {
    let fake = server(Cert::SelfSigned).await;
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    w.connect(&params(&fake, &[("host_key", &pin(LEAF))]), &c).await.unwrap().unwrap();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ServerIdentityChanged);
    assert!(fake.seen().is_empty());
    w.connect(&params(&fake, &[("host_key", "tls-spki-sha256 ***")]), &c).await.unwrap();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ServerIdentityChanged);
    w.connect(&params(&fake, &[("host_key", &pin(SELF))]), &c).await.unwrap();
    w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap();
    assert_eq!(fake.methods(), ["PROPFIND"]);
}

#[tokio::test]
async fn sign_in_sends_basic_credentials() {
    let fake = server(Cert::Trusted).await;
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    w.connect(&params(&fake, &[]), &c).await.unwrap();
    let e = w.authenticate(&creds("alice", "wrong"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AuthFailed);
    w.connect(&params(&fake, &[]), &c).await.unwrap();
    w.authenticate(&creds("", "secret"), None, &c).await.unwrap();
    let seen = fake.seen();
    let last = seen.last().unwrap();
    assert_eq!(last.headers.get("authorization").unwrap(), AUTH);
    assert_eq!(last.headers.get("depth").unwrap(), "0");
    assert_eq!(last.path, b"/");
    assert_eq!(
        w.capabilities().names(),
        ["ETags", "NativeNoReplace", "ReadHandles", "ServerCopy", "ServerCopyRecursive"]
    );
    fake.with(|s| s.quota = Some(("-3", "20")));
    w.connect(&params(&fake, &[]), &c).await.unwrap();
    w.authenticate(&creds("", "secret"), None, &c).await.unwrap();
    assert!(w.capabilities().names().contains(&"SpaceInfo"));
}

const CLOUD: &str = "/cloud/remote.php/dav/files/alice";

async fn cloud(dasl: Option<&'static str>) -> Fake {
    let fake = server(Cert::Trusted).await;
    for dir in ["/cloud", "/cloud/remote.php", "/cloud/remote.php/dav", "/cloud/remote.php/dav/files", CLOUD]
    {
        fake.put(dir, Node::Dir);
    }
    fake.with(|s| {
        s.owncloud = true;
        s.dasl = dasl;
    });
    fake
}

#[tokio::test]
async fn owncloud_and_nextcloud_folders_have_etags_that_cover_what_is_below() {
    let fake = cloud(None).await;
    fake.put(&format!("{CLOUD}/a"), Node::Dir);
    fake.put(&format!("{CLOUD}/a/deep"), Node::Dir);
    fake.put(&format!("{CLOUD}/b"), Node::Dir);
    let mut w = signed_in(&fake, CLOUD).await;
    let c = CancelToken::new();
    assert_eq!(
        w.capabilities().names(),
        ["DeepETags", "ETags", "NativeNoReplace", "ReadHandles", "ServerCopy", "ServerCopyRecursive"]
    );
    let etag = |e: Entry| e.etag;
    let (root, a, b) = (
        etag(w.stat(b"", false, &c).await.unwrap()),
        etag(w.stat(b"a", false, &c).await.unwrap()),
        etag(w.stat(b"b", false, &c).await.unwrap()),
    );
    assert!(!root.is_empty() && !a.is_empty());
    fake.put(&format!("{CLOUD}/a/deep/new.txt"), file(b"n"));
    assert_ne!(etag(w.stat(b"", false, &c).await.unwrap()), root);
    assert_ne!(etag(w.stat(b"a", false, &c).await.unwrap()), a);
    assert_eq!(etag(w.stat(b"b", false, &c).await.unwrap()), b);

    let plain = server(Cert::Trusted).await;
    let w = signed_in(&plain, "").await;
    assert!(!w.capabilities().has(Capability::DeepETags), "a server that does not know oc:fileid");
    assert!(!w.capabilities().has(Capability::Search));
    assert_eq!(plain.methods(), Vec::<String>::new());
}

#[tokio::test]
async fn search_is_offered_where_the_dav_root_says_so() {
    for (dasl, base, offered) in [
        (Some("<DAV:basicsearch>"), CLOUD, true),
        (Some("<DAV:sql>, <DAV:basicsearch>"), CLOUD, true),
        (Some("<DAV:sql>"), CLOUD, false),
        (None, CLOUD, false),
    ] {
        let fake = cloud(dasl).await;
        let mut w = Webdav::with_anchors(anchors());
        let c = CancelToken::new();
        w.connect(&params(&fake, &[("base_path", base)]), &c).await.unwrap();
        w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap();
        assert_eq!(w.capabilities().has(Capability::Search), offered, "{dasl:?}");
        let seen = fake.seen();
        let asked: Vec<(&str, &[u8])> = seen.iter().map(|s| (s.method.as_str(), s.path.as_slice())).collect();
        assert_eq!(asked, [("PROPFIND", CLOUD.as_bytes()), ("OPTIONS", b"/cloud/remote.php/dav/")]);
        if !offered {
            let e = w.search(b"", "x", 10, &mut Collect::default(), &c).await.unwrap_err();
            assert_eq!(e.name, ErrorName::Unsupported);
            assert!(fake.state.lock().unwrap().searches.is_empty(), "no request without the offer");
        }
    }
    let fake = server(Cert::Trusted).await;
    fake.with(|s| s.owncloud = true);
    let w = signed_in(&fake, "").await;
    assert!(w.capabilities().has(Capability::DeepETags) && !w.capabilities().has(Capability::Search));
    assert_eq!(fake.methods(), Vec::<String>::new(), "no question outside the ownCloud layout");
}

#[tokio::test]
async fn search_finds_names_below_a_folder() {
    let fake = cloud(Some("<DAV:basicsearch>")).await;
    for dir in ["Docs", "Docs/Tax 2026", "Docs/Tax 2026/deep", "Pics"] {
        fake.put(&format!("{CLOUD}/{dir}"), Node::Dir);
    }
    fake.put(&format!("{CLOUD}/Docs/tax-return.pdf"), file(b"12345"));
    fake.put(&format!("{CLOUD}/Docs/Tax 2026/deep/TAX notes & more.txt"), file(b"1"));
    fake.put(&format!("{CLOUD}/Docs/other.txt"), file(b"1"));
    fake.put(&format!("{CLOUD}/Pics/tax.jpg"), file(b"1"));
    let mut w = signed_in(&fake, CLOUD).await;
    let c = CancelToken::new();
    let mut found = Collect::default();
    w.search(b"/Docs", "tax", 100, &mut found, &c).await.unwrap();
    assert_eq!(names(&found.0), ["Tax 2026", "Tax 2026/deep/TAX notes & more.txt", "tax-return.pdf"]);
    let pdf = found.0.iter().find(|e| e.name == b"tax-return.pdf").unwrap();
    assert_eq!((pdf.kind, pdf.size, pdf.mtime_ms), (EntryType::File, Some(5), Some(MTIME_MS)));
    assert_eq!(found.0[0].kind, EntryType::Directory);
    let seen = fake.seen();
    let last = seen.last().unwrap();
    assert_eq!((last.method.as_str(), last.path.as_slice()), ("SEARCH", &b"/cloud/remote.php/dav/"[..]));
    assert!(last.headers.get("content-type").unwrap().to_str().unwrap().starts_with("text/xml"));
    let body = fake.state.lock().unwrap().searches.last().unwrap().clone();
    assert!(body.contains("<d:href>/files/alice/Docs</d:href><d:depth>infinity</d:depth>"), "{body}");
    assert!(body.contains("<d:literal>%tax%</d:literal>") && body.contains("<d:nresults>100</d:nresults>"));

    let mut everywhere = Collect::default();
    w.search(b"", "TAX", 100, &mut everywhere, &c).await.unwrap();
    assert_eq!(everywhere.0.len(), 4);
    assert!(names(&everywhere.0).contains(&"Pics/tax.jpg".to_owned()));
    let mut two = Collect::default();
    w.search(b"", "tax", 2, &mut two, &c).await.unwrap();
    assert_eq!(two.0.len(), 2, "the limit holds");
    let mut escaped = Collect::default();
    w.search(b"Docs", "notes & more", 5, &mut escaped, &c).await.unwrap();
    assert_eq!(names(&escaped.0), ["Tax 2026/deep/TAX notes & more.txt"]);
    let body = fake.state.lock().unwrap().searches.last().unwrap().clone();
    assert!(body.contains("<d:literal>%notes &amp; more%</d:literal>"), "{body}");
    assert_eq!(
        w.search(b"/a/../b", "x", 5, &mut Collect::default(), &c).await.unwrap_err().name,
        ErrorName::InvalidName
    );
}

#[tokio::test]
async fn search_results_are_checked_and_handed_on_in_batches() {
    let fake = cloud(Some("<DAV:basicsearch>")).await;
    let mut w = signed_in(&fake, CLOUD).await;
    let c = CancelToken::new();
    let response = |href: &str| {
        format!(
            "<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype/></d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )
    };
    let hostile = [
        "/cloud/remote.php/dav/files/alice/Docs/ok.txt",
        "/cloud/remote.php/dav/files/alice/Docs/",
        "/cloud/remote.php/dav/files/alice/Docs/../../bob/secret",
        "/cloud/remote.php/dav/files/bob/x",
        "/etc/passwd",
        "https://evil.example/cloud/remote.php/dav/files/alice/Docs/sub/also%20ok",
    ]
    .map(response)
    .concat();
    let body: &'static str = Box::leak(
        format!(r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{hostile}</d:multistatus>"#)
            .into_boxed_str(),
    );
    let search = Method::from_bytes(b"SEARCH").unwrap();
    fake.with(|s| s.canned.push((search.clone(), StatusCode::MULTI_STATUS, vec![], body)));
    let mut found = Collect::default();
    w.search(b"Docs", "ok", 10, &mut found, &c).await.unwrap();
    assert_eq!(names(&found.0), ["ok.txt", "sub/also ok"], "only what lies below the folder");

    for (code, name) in [
        (StatusCode::NOT_IMPLEMENTED, ErrorName::Unsupported),
        (StatusCode::METHOD_NOT_ALLOWED, ErrorName::Unsupported),
        (StatusCode::BAD_REQUEST, ErrorName::ProtocolError),
        (StatusCode::OK, ErrorName::ProtocolError),
    ] {
        fake.with(|s| s.canned.push((search.clone(), code, vec![], "")));
        let e = w.search(b"Docs", "ok", 10, &mut Collect::default(), &c).await.unwrap_err();
        assert_eq!(e.name, name, "{code}");
    }

    for i in 0..600 {
        fake.put(&format!("{CLOUD}/hit-{i:03}"), file(b"1"));
    }
    struct Batches(Vec<usize>, usize);
    impl ListSink for Batches {
        fn entries(&mut self, batch: &[Entry]) -> bool {
            self.0.push(batch.len());
            self.0.len() < self.1
        }
    }
    let mut all = Batches(Vec::new(), usize::MAX);
    w.search(b"", "hit", 1000, &mut all, &c).await.unwrap();
    assert_eq!(all.0, [SEARCH_BATCH, SEARCH_BATCH, 600 - 2 * SEARCH_BATCH]);
    let mut stop = Batches(Vec::new(), 1);
    assert_eq!(w.search(b"", "hit", 1000, &mut stop, &c).await.unwrap_err().name, ErrorName::Canceled);
    assert_eq!(stop.0.len(), 1);
    let canceled = CancelToken::new();
    canceled.cancel();
    let e = w.search(b"", "hit", 1000, &mut Collect::default(), &canceled).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
}

#[tokio::test]
async fn an_open_server_signs_in_without_credentials() {
    let fake = Fake::start(Cert::Trusted).await;
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    let mut p = params(&fake, &[]);
    p.username.clear();
    w.connect(&p, &c).await.unwrap();
    w.authenticate(&creds("", ""), None, &c).await.unwrap();
    assert!(fake.seen()[0].headers.get("authorization").is_none());
}

#[test]
fn basic_credentials() {
    assert_eq!(basic("", b"").unwrap(), None);
    assert_eq!(basic("alice", b"secret").unwrap().unwrap(), AUTH);
    assert!(basic("alice", b"secret").unwrap().unwrap().is_sensitive());
    assert_eq!(basic("", b"x").unwrap().unwrap(), "Basic Ong=");
    assert_eq!(basic("a:b", b"x").unwrap_err().name, ErrorName::AuthFailed);
    assert_eq!(basic("ä", "ö".as_bytes()).unwrap().unwrap(), "Basic w6Q6w7Y=");
}

#[tokio::test]
async fn sign_in_checks_the_folder() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    let mut w = Webdav::with_anchors(anchors());
    let c = CancelToken::new();
    w.connect(&params(&fake, &[("base_path", "/missing")]), &c).await.unwrap();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!((e.name, e.message.as_str()), (ErrorName::NotFound, "No WebDAV folder at this address"));
    w.connect(&params(&fake, &[("base_path", "/f")]), &c).await.unwrap();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotADirectory);
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"PROPFIND").unwrap(), StatusCode::OK, vec![], "<html/>"));
    });
    w.connect(&params(&fake, &[]), &c).await.unwrap();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError);
    assert_eq!(w.stat(b"/", false, &c).await.unwrap_err().message, "Not signed in");
}

#[tokio::test]
async fn authenticate_needs_a_fresh_connection() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "/").await;
    let c = CancelToken::new();
    let e = w.authenticate(&creds("alice", "secret"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Internal);
    w.stat(b"/", false, &c).await.unwrap();
    let mut idle = Webdav::new();
    assert_eq!(idle.authenticate(&creds("a", "b"), None, &c).await.unwrap_err().name, ErrorName::Internal);
}

#[test]
fn settings_from_params() {
    let p = Params {
        host: "[::1]".into(),
        port: 0,
        options: [("base_path".to_owned(), Value::Str("dav//x/".into()))].into(),
        ..Params::default()
    };
    let s = Settings::of(&p).unwrap();
    assert_eq!((s.target.host.as_str(), s.target.port), ("::1", 443));
    assert_eq!(s.base, Base::new("/dav/x").unwrap());
    assert_eq!(
        (s.target.connect_timeout, s.target.request_timeout),
        (DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT)
    );
    assert_eq!(s.pin, None);
    assert_eq!(s.target.stale_after, Duration::from_secs(1));
    let p = Params {
        host: "nas".into(),
        port: 8443,
        connect_timeout_ms: 5,
        request_timeout_ms: 6,
        options: [("host_key".to_owned(), Value::Str("k".into()))].into(),
        ..Params::default()
    };
    let s = Settings::of(&p).unwrap();
    assert_eq!(s.target.port, 8443);
    assert_eq!(
        (s.target.connect_timeout, s.target.request_timeout),
        (Duration::from_millis(5), Duration::from_millis(6))
    );
    assert_eq!(s.pin.as_deref(), Some("k"));
    let empty_pin = Params {
        host: "nas".into(),
        options: [("host_key".to_owned(), Value::Str(String::new()))].into(),
        ..Params::default()
    };
    assert_eq!(Settings::of(&empty_pin).unwrap().pin, None);
    for host in ["", "a@b", "a/b"] {
        assert_eq!(
            Settings::of(&Params { host: host.into(), ..Params::default() }).unwrap_err().name,
            ErrorName::Internal
        );
    }
    assert_eq!(
        Settings::of(&Params { host: "h".into(), port: 70_000, ..Params::default() }).unwrap_err().name,
        ErrorName::Internal
    );
    let dots = Params {
        host: "h".into(),
        options: [("base_path".to_owned(), Value::Str("/a/..".into()))].into(),
        ..Params::default()
    };
    assert_eq!(Settings::of(&dots).unwrap_err().name, ErrorName::InvalidName);
}

#[tokio::test]
async fn stat_files_folders_and_missing_ones() {
    let fake = server(Cert::Trusted).await;
    fake.put("/dav", Node::Dir);
    fake.put("/dav/d", Node::Dir);
    fake.put("/dav/d/f x", file(b"hello"));
    let mut w = signed_in(&fake, "/dav").await;
    let c = CancelToken::new();
    let f = w.stat(b"/d/f x", true, &c).await.unwrap();
    assert_eq!(
        f,
        Entry {
            name: b"f x".to_vec(),
            kind: EntryType::File,
            size: Some(5),
            mtime_ms: Some(MTIME_MS),
            etag: b"\"5\"".to_vec(),
            content_type: "application/octet-stream".into(),
            ..Entry::default()
        }
    );
    assert_eq!(fake.seen()[0].path, b"/dav/d/f x");
    assert_eq!(fake.seen()[0].headers.get("depth").unwrap(), "0");
    let d = w.stat(b"d", false, &c).await.unwrap();
    assert_eq!((d.name.as_slice(), d.kind, d.size), (&b"d"[..], EntryType::Directory, None));
    let root = w.stat(b"", false, &c).await.unwrap();
    assert_eq!((root.name.as_slice(), root.kind), (&b""[..], EntryType::Directory));
    assert_eq!(w.stat(b"/nope", false, &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(w.stat(b"/d/..", false, &c).await.unwrap_err().name, ErrorName::InvalidName);
}

#[tokio::test]
async fn an_empty_multistatus_is_not_found() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "/").await;
    let ms = r#"<d:multistatus xmlns:d="DAV:"/>"#;
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"PROPFIND").unwrap(), StatusCode::MULTI_STATUS, vec![], ms));
    });
    assert_eq!(w.stat(b"/x", false, &CancelToken::new()).await.unwrap_err().name, ErrorName::NotFound);
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"PROPFIND").unwrap(), StatusCode::MULTI_STATUS, vec![], ms));
    });
    let e = w
        .list(b"/x", ListOptions::default(), &mut Collect::default(), &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
}

#[tokio::test]
async fn list_gives_children_in_batches() {
    let fake = server(Cert::Trusted).await;
    fake.put("/d", Node::Dir);
    for n in ["a", "b", "c"] {
        fake.put(&format!("/d/{n}"), file(n.as_bytes()));
    }
    fake.put("/d/sub", Node::Dir);
    fake.put("/d/sub/deep", file(b""));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    struct Batches(Vec<usize>);
    impl ListSink for Batches {
        fn entries(&mut self, batch: &[Entry]) -> bool {
            self.0.push(batch.len());
            true
        }
    }
    let mut b = Batches(Vec::new());
    w.list(b"/d", ListOptions { batch_size: 3, resolve_symlink_types: false }, &mut b, &c).await.unwrap();
    assert_eq!(b.0, [3, 1]);
    let mut all = Collect::default();
    w.list(b"/d/", ListOptions::default(), &mut all, &c).await.unwrap();
    assert_eq!(names(&all.0), ["a", "b", "c", "sub"]);
    assert_eq!(fake.seen().last().unwrap().path, b"/d");
    assert_eq!(fake.seen().last().unwrap().headers.get("depth").unwrap(), "1");
    let mut none = Collect::default();
    w.list(b"/d/sub/deep", ListOptions::default(), &mut none, &c).await.map(drop).unwrap_err();
    assert_eq!(
        w.list(b"/d/a", ListOptions::default(), &mut none, &c).await.unwrap_err().name,
        ErrorName::NotADirectory
    );
    assert_eq!(
        w.list(b"/gone", ListOptions::default(), &mut none, &c).await.unwrap_err().name,
        ErrorName::NotFound
    );
    struct Stop;
    impl ListSink for Stop {
        fn entries(&mut self, _: &[Entry]) -> bool {
            false
        }
    }
    assert_eq!(
        w.list(b"/d", ListOptions::default(), &mut Stop, &c).await.unwrap_err().name,
        ErrorName::Canceled
    );
}

#[tokio::test]
async fn an_empty_folder_lists_nothing() {
    let fake = server(Cert::Trusted).await;
    fake.put("/d", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let mut sink = Collect::default();
    w.list(b"/d", ListOptions::default(), &mut sink, &CancelToken::new()).await.unwrap();
    assert!(sink.0.is_empty());
}

#[tokio::test]
async fn hostile_listings_yield_only_children() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "/").await;
    let r = |href: &str| {
        format!(
            "<d:response><d:href>{href}</d:href><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )
    };
    let body = format!(
        r#"<d:multistatus xmlns:d="DAV:">{}</d:multistatus>"#,
        [
            r("/d/").replace("<d:resourcetype/>", "<d:resourcetype><d:collection/></d:resourcetype>"),
            r("/d/ok"),
            r("/etc/passwd"),
            r("/d/a/b"),
            r("/d/.."),
            r("/d/%2e%2e"),
            r("https://evil/d/x"),
            r("/d//")
        ]
        .concat()
    );
    let body: &'static str = Box::leak(body.into_boxed_str());
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"PROPFIND").unwrap(), StatusCode::MULTI_STATUS, vec![], body));
    });
    let mut all = Collect::default();
    w.list(b"/d", ListOptions::default(), &mut all, &CancelToken::new()).await.unwrap();
    assert_eq!(names(&all.0), ["ok", "x"]);
}

#[tokio::test]
async fn make_dir_exclusive_or_not() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b""));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    w.make_dir(b"/d", true, &c).await.unwrap();
    assert_eq!(fake.get("/d"), Some(Node::Dir));
    assert_eq!(w.make_dir(b"/d", true, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    w.make_dir(b"/d", false, &c).await.unwrap();
    assert_eq!(w.make_dir(b"/f", false, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    assert_eq!(w.make_dir(b"/no/d", false, &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(fake.methods().first().unwrap(), "MKCOL");
}

#[tokio::test]
async fn remove_files_and_empty_folders_only() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    fake.put("/d", Node::Dir);
    fake.put("/full", Node::Dir);
    fake.put("/full/x", file(b""));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    assert_eq!(w.remove_file(b"/d", &c).await.unwrap_err().name, ErrorName::IsADirectory);
    assert_eq!(w.remove_dir(b"/f", &c).await.unwrap_err().name, ErrorName::NotADirectory);
    assert_eq!(w.remove_dir(b"/full", &c).await.unwrap_err().name, ErrorName::DirectoryNotEmpty);
    assert_eq!(fake.get("/full/x"), Some(file(b"")));
    assert_eq!(w.remove_dir(b"/", &c).await.unwrap_err().name, ErrorName::PermissionDenied);
    assert_eq!(w.remove_file(b"/gone", &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(w.remove_dir(b"/gone", &c).await.unwrap_err().name, ErrorName::NotFound);
    w.remove_file(b"/f", &c).await.unwrap();
    w.remove_dir(b"/d", &c).await.unwrap();
    assert_eq!((fake.get("/f"), fake.get("/d")), (None, None));
    let deletes: Vec<Vec<u8>> =
        fake.seen().into_iter().filter(|s| s.method == Method::DELETE).map(|s| s.path).collect();
    assert_eq!(deletes, [b"/f".to_vec(), b"/d/".to_vec()]);
}

#[tokio::test]
async fn rename_modes() {
    let fake = server(Cert::Trusted).await;
    fake.put("/a", file(b"a"));
    fake.put("/b", file(b"b"));
    fake.put("/d", Node::Dir);
    fake.put("/d/in", file(b"i"));
    fake.put("/e", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    assert_eq!(
        w.rename(b"/a", b"/b", RenameMode::NoReplace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    let mv = fake.seen().into_iter().find(|s| s.method.as_str() == "MOVE").unwrap();
    assert_eq!(mv.headers.get("overwrite").unwrap(), "F");
    let origin = format!("https://localhost:{}", fake.addr.port());
    assert_eq!(mv.headers.get("destination").unwrap().to_str().unwrap(), format!("{origin}/b"));
    w.rename(b"/a", b"/b", RenameMode::Replace, &c).await.unwrap();
    assert_eq!((fake.get("/a"), fake.get("/b")), (None, Some(file(b"a"))));
    assert_eq!(
        w.rename(b"/b", b"/e", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    assert_eq!(
        w.rename(b"/d", b"/b", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    assert_eq!(
        w.rename(b"/gone", b"/x", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::NotFound
    );
    assert_eq!(
        w.rename(b"/b", b"/no/x", RenameMode::Replace, &c).await.unwrap_err().name,
        ErrorName::NotFound
    );
    fake.clear_seen();
    w.rename(b"/d", b"/d 2", RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!((fake.get("/d/in"), fake.get("/d 2/in")), (None, Some(file(b"i"))));
    let mv = fake.seen().into_iter().find(|s| s.method.as_str() == "MOVE").unwrap();
    assert_eq!(mv.path, b"/d/");
    assert_eq!(mv.headers.get("destination").unwrap().to_str().unwrap(), format!("{origin}/d%202"));
    fake.clear_seen();
    w.rename(b"/b", b"b", RenameMode::NoReplace, &c).await.unwrap();
    assert!(!fake.methods().contains(&"MOVE".to_owned()), "same path: nothing to do");
    w.rename(b"/b", b"/c", RenameMode::Replace, &c).await.unwrap();
    assert_eq!((fake.get("/b"), fake.get("/c")), (None, Some(file(b"a"))));
    fake.with(|s| s.forbidden = Some(b"/locked".to_vec()));
    fake.clear_seen();
    let e = w.rename(b"/c", b"/locked", RenameMode::Replace, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::PermissionDenied);
    assert!(!fake.methods().contains(&"MOVE".to_owned()));
}

#[tokio::test]
async fn copy_files_and_trees() {
    let fake = server(Cert::Trusted).await;
    fake.put("/a", file(b"a"));
    fake.put("/d", Node::Dir);
    fake.put("/d/in", file(b"i"));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    w.copy(b"/a", b"/b", false, RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!((fake.get("/a"), fake.get("/b")), (Some(file(b"a")), Some(file(b"a"))));
    let cp = fake.seen().into_iter().find(|s| s.method.as_str() == "COPY").unwrap();
    assert_eq!(cp.headers.get("depth").unwrap(), "0");
    assert_eq!(
        w.copy(b"/d", b"/e", false, RenameMode::NoReplace, &c).await.unwrap_err().name,
        ErrorName::IsADirectory
    );
    fake.clear_seen();
    w.copy(b"/d", b"/e", true, RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!((fake.get("/d/in"), fake.get("/e/in")), (Some(file(b"i")), Some(file(b"i"))));
    let cp = fake.seen().into_iter().find(|s| s.method.as_str() == "COPY").unwrap();
    assert_eq!(cp.headers.get("depth").unwrap(), "infinity");
    assert_eq!(
        w.copy(b"/a", b"/b", false, RenameMode::NoReplace, &c).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
}

#[tokio::test]
async fn free_space_from_quota() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    assert_eq!(w.space_info(b"/", &c).await.unwrap_err().name, ErrorName::Unsupported);
    fake.with(|s| s.quota = Some(("100", "20")));
    assert_eq!(
        w.space_info(b"/", &c).await.unwrap(),
        SpaceInfo { free: Some(100), total: Some(120), used: Some(20) }
    );
    fake.with(|s| s.quota = Some(("-3", "20")));
    assert_eq!(w.space_info(b"/", &c).await.unwrap(), SpaceInfo { free: None, total: None, used: Some(20) });
    fake.with(|s| s.quota = Some(("18446744073709551615", "1")));
    assert_eq!(w.space_info(b"/", &c).await.unwrap().free, None);
}

#[tokio::test]
async fn unresolved_paths_are_explained_by_their_parents() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    fake.put("/d", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let propfind = || Method::from_bytes(b"PROPFIND").unwrap();
    fake.with(|s| s.canned.push((propfind(), StatusCode::BAD_REQUEST, vec![], "")));
    assert_eq!(w.stat(b"/f/below", true, &c).await.unwrap_err().name, ErrorName::NotADirectory);
    fake.with(|s| s.canned.extend((0..2).map(|_| (propfind(), StatusCode::BAD_REQUEST, vec![], ""))));
    assert_eq!(w.stat(b"f/a/b", true, &c).await.unwrap_err().name, ErrorName::NotADirectory);
    let mut sink = Collect::default();
    fake.with(|s| s.canned.push((propfind(), StatusCode::BAD_REQUEST, vec![], "")));
    let e = w.list(b"/f/x", ListOptions::default(), &mut sink, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotADirectory);
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"MKCOL").unwrap(), StatusCode::BAD_REQUEST, vec![], ""));
    });
    assert_eq!(w.make_dir(b"/f/new", true, &c).await.unwrap_err().name, ErrorName::NotADirectory);
    fake.with(|s| {
        s.canned.push((Method::from_bytes(b"MOVE").unwrap(), StatusCode::INTERNAL_SERVER_ERROR, vec![], ""));
    });
    assert_eq!(
        w.rename(b"/f", b"/missing/f", RenameMode::NoReplace, &c).await.unwrap_err().name,
        ErrorName::NotFound
    );
    for to in [&b"/d/g"[..], b"/g"] {
        fake.with(|s| {
            s.canned.push((
                Method::from_bytes(b"MOVE").unwrap(),
                StatusCode::INTERNAL_SERVER_ERROR,
                vec![],
                "",
            ));
        });
        let e = w.rename(b"/f", to, RenameMode::NoReplace, &c).await.unwrap_err();
        assert_eq!((e.name, e.detail.as_str()), (ErrorName::ProtocolError, "HTTP 500 Internal Server Error"));
    }
    fake.with(|s| {
        s.canned.push((propfind(), StatusCode::BAD_REQUEST, vec![], ""));
        s.canned.push((propfind(), StatusCode::FORBIDDEN, vec![], ""));
    });
    let e = w.stat(b"/f/a/b", true, &c).await.unwrap_err();
    assert_eq!((e.name, e.detail.as_str()), (ErrorName::ProtocolError, "HTTP 400 Bad Request"));
    fake.clear_seen();
    fake.with(|s| s.canned.push((propfind(), StatusCode::FORBIDDEN, vec![], "")));
    assert_eq!(w.stat(b"/f/below", true, &c).await.unwrap_err().name, ErrorName::PermissionDenied);
    assert_eq!(fake.seen().len(), 1);
}

#[tokio::test]
async fn names_that_are_not_utf8_are_flagged() {
    let fake = server(Cert::Trusted).await;
    fake.with(|s| drop(s.tree.insert(b"/caf\xe9".to_vec(), file(b"x"))));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let odd = w.stat(b"/caf\xe9", true, &c).await.unwrap();
    assert_eq!((odd.name, odd.flags), (b"caf\xe9".to_vec(), EntryFlags::NAME_NOT_UTF8));
    assert_eq!(w.stat(b"/caf\xc3\xa9", true, &c).await.unwrap_err().name, ErrorName::NotFound);
}

#[tokio::test]
async fn download_whole_and_ranges() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"0123456789"));
    fake.put("/d", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let get = async |w: &mut Webdav, offset, length| {
        let mut out = Out::default();
        let mut p = Moves::quiet();
        w.download(b"/f", offset, length, &mut out, &mut p, &c).await.map(|()| (out.0, p.last))
    };
    assert_eq!(get(&mut w, 0, None).await.unwrap(), (b"0123456789".to_vec(), (10, Some(10))));
    assert_eq!(get(&mut w, 3, Some(4)).await.unwrap(), (b"3456".to_vec(), (4, Some(4))));
    assert_eq!(get(&mut w, 8, None).await.unwrap(), (b"89".to_vec(), (2, Some(2))));
    assert_eq!(get(&mut w, 8, Some(5)).await.unwrap().0, b"89");
    assert_eq!(get(&mut w, 10, None).await.unwrap().0, b"");
    assert_eq!(get(&mut w, 3, Some(0)).await.unwrap().0, b"");
    let ranges: Vec<String> = fake
        .seen()
        .iter()
        .filter(|s| s.method == Method::GET)
        .map(|s| s.headers.get("range").map_or_else(|| "-".into(), |r| r.to_str().unwrap().to_owned()))
        .collect();
    assert_eq!(ranges, ["-", "bytes=3-6", "bytes=8-", "bytes=8-12", "bytes=10-"]);
    fake.with(|s| s.no_ranges = true);
    assert_eq!(get(&mut w, 3, Some(4)).await.unwrap().0, b"3456");
    assert_eq!(get(&mut w, 12, None).await.unwrap().0, b"");
    let mut out = Out::default();
    let e = w.download(b"/d", 0, None, &mut out, &mut Moves::quiet(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::IsADirectory);
    let e = w.download(b"/gone", 0, None, &mut out, &mut Moves::quiet(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
}

#[tokio::test]
async fn a_range_answer_for_another_offset_is_refused() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"0123456789"));
    let mut w = signed_in(&fake, "").await;
    fake.with(|s| {
        s.canned.push((
            Method::GET,
            StatusCode::PARTIAL_CONTENT,
            vec![("content-range", "bytes 0-3/10")],
            "0123",
        ));
    });
    let e = w
        .download(b"/f", 2, Some(4), &mut Out::default(), &mut Moves::quiet(), &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError);
}

#[tokio::test]
async fn a_download_stops_when_progress_says_so() {
    let fake = server(Cert::Trusted).await;
    let big = vec![7u8; 3 * 1024 * 1024];
    fake.put("/f", Node::File(big.clone()));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let mut p = Moves { after: Some(1), last: (0, None) };
    let e = w.download(b"/f", 0, None, &mut Out::default(), &mut p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    let mut out = Out::default();
    w.download(b"/f", 0, None, &mut out, &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(out.0, big);
}

#[tokio::test]
async fn uploads() {
    let fake = server(Cert::Trusted).await;
    fake.put("/d", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let new = WriteOptions { disposition: Disposition::CreateNew, ..WriteOptions::default() };
    let replace = WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() };
    let mut p = Moves::quiet();
    w.upload(b"/f", &new, &mut Data(data.clone(), 0, true), &mut p, &c).await.unwrap();
    assert_eq!(fake.get("/f"), Some(Node::File(data.clone())));
    assert_eq!(p.last, (1_000_000, Some(1_000_000)));
    let put = fake.seen().into_iter().find(|s| s.method == Method::PUT).unwrap();
    assert_eq!(put.headers.get("content-length").unwrap(), "1000000");
    assert_eq!(put.headers.get("if-none-match").unwrap(), "*");
    let e =
        w.upload(b"/f", &new, &mut Data(b"x".to_vec(), 0, true), &mut Moves::quiet(), &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    fake.clear_seen();
    w.upload(b"/f", &replace, &mut Data(b"new".to_vec(), 0, false), &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(fake.get("/f"), Some(file(b"new")));
    let put = fake.seen().into_iter().find(|s| s.method == Method::PUT).unwrap();
    assert!(put.headers.get("if-none-match").is_none());
    assert_eq!(put.headers.get("transfer-encoding").unwrap(), "chunked");
    let e = w
        .upload(b"/d", &replace, &mut Data(b"x".to_vec(), 0, true), &mut Moves::quiet(), &c)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::IsADirectory);
    let e = w
        .upload(b"/no/f", &replace, &mut Data(b"x".to_vec(), 0, true), &mut Moves::quiet(), &c)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    let resume =
        WriteOptions { disposition: Disposition::Resume, resume_offset: 3, ..WriteOptions::default() };
    let e = w
        .upload(b"/f", &resume, &mut Data(b"x".to_vec(), 0, true), &mut Moves::quiet(), &c)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::Unsupported);
    w.upload(b"/empty", &new, &mut Data(Vec::new(), 0, true), &mut Moves::quiet(), &c).await.unwrap();
    assert_eq!(fake.get("/empty"), Some(file(b"")));
}

struct Zeros {
    left: usize,
    largest: usize,
}

impl Source for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        self.largest = self.largest.max(buf.len());
        let n = buf.len().min(self.left);
        buf[..n].fill(0);
        self.left -= n;
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        None
    }
}

#[tokio::test]
async fn uploads_read_256_kib_at_a_time() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let mut source = Zeros { left: 1_000_000, largest: 0 };
    w.upload(b"/f", &WriteOptions::default(), &mut source, &mut Moves::quiet(), &CancelToken::new())
        .await
        .unwrap();
    assert_eq!(source.largest, 262_144);
}

#[tokio::test]
async fn a_failed_upload_does_not_reuse_its_connection() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let upload = async |w: &mut Webdav, path: &[u8]| {
        let mut data = Data(b"x".to_vec(), 0, true);
        w.upload(path, &WriteOptions::default(), &mut data, &mut Moves::quiet(), &c).await
    };
    let connections = || fake.state.lock().unwrap().connections;
    upload(&mut w, b"/f").await.unwrap();
    let after_success = connections();
    w.stat(b"/f", false, &c).await.unwrap();
    assert_eq!(connections(), after_success);
    assert_eq!(upload(&mut w, b"/no/f").await.unwrap_err().name, ErrorName::NotFound);
    let after_failure = connections();
    w.stat(b"/f", false, &c).await.unwrap();
    assert_eq!(connections(), after_failure + 1);
}

#[tokio::test]
async fn a_server_without_ranges_is_read_up_to_the_length() {
    let fake = server(Cert::Trusted).await;
    let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    fake.put("/f", Node::File(data.clone()));
    fake.with(|s| s.no_ranges = true);
    let mut w = signed_in(&fake, "").await;
    let mut out = Out::default();
    w.download(b"/f", 1000, Some(600_000), &mut out, &mut Moves::quiet(), &CancelToken::new()).await.unwrap();
    assert_eq!(out.0, data[1000..601_000]);
}

#[tokio::test]
async fn an_upload_stops_when_progress_says_so_and_the_next_call_works() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let data = vec![1u8; 2_000_000];
    let mut p = Moves { after: Some(1), last: (0, None) };
    let e =
        w.upload(b"/f", &WriteOptions::default(), &mut Data(data, 0, true), &mut p, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert_eq!(fake.get("/f"), None, "the server got no complete body");
    w.stat(b"/", false, &c).await.unwrap();
}

#[tokio::test]
async fn read_handles_read_ranges() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"0123456789"));
    fake.put("/d", Node::Dir);
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let mut h = w.open_read(b"/f", &c).await.unwrap();
    assert_eq!(h.size(), Some(10));
    let mut buf = [0u8; 4];
    assert_eq!(h.read(2, &mut buf, &c).await.unwrap(), 4);
    assert_eq!(&buf, b"2345");
    assert_eq!(h.read(8, &mut buf, &c).await.unwrap(), 2);
    assert_eq!(&buf[..2], b"89");
    assert_eq!(h.read(10, &mut buf, &c).await.unwrap(), 0);
    assert_eq!(h.read(0, &mut [], &c).await.unwrap(), 0);
    fake.with(|s| s.no_ranges = true);
    assert_eq!(h.read(5, &mut buf, &c).await.unwrap(), 4);
    assert_eq!(&buf, b"5678");
    h.read_ahead(0, 10);
    w.stat(b"/f", false, &c).await.unwrap();
    assert_eq!(w.open_read(b"/d", &c).await.unwrap_err().name, ErrorName::IsADirectory);
    w.disconnect().await;
    assert_eq!(h.read(0, &mut buf, &c).await.unwrap_err().name, ErrorName::ConnectionLost);
    h.close(&c).await.unwrap();
}

#[tokio::test]
async fn a_server_that_closes_each_connection_is_reopened() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    let mut w = signed_in(&fake, "").await;
    fake.with(|s| s.close = true);
    let c = CancelToken::new();
    let before = fake.state.lock().unwrap().connections;
    for _ in 0..3 {
        w.stat(b"/f", false, &c).await.unwrap();
    }
    w.upload(b"/g", &WriteOptions::default(), &mut Data(b"y".to_vec(), 0, true), &mut Moves::quiet(), &c)
        .await
        .unwrap();
    w.keep_alive(&c).await.unwrap();
    assert!(fake.state.lock().unwrap().connections >= before + 4);
    assert_eq!(fake.methods().last().unwrap(), "OPTIONS");
}

#[tokio::test]
async fn a_request_the_server_drops_on_a_reused_connection_is_sent_again() {
    let fake = server(Cert::Trusted).await;
    fake.put("/f", file(b"x"));
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    fake.with(|s| s.drop_after = Some(1));
    let before = fake.state.lock().unwrap().connections;
    w.stat(b"/f", false, &c).await.unwrap();
    w.stat(b"/f", false, &c).await.unwrap();
    assert_eq!(fake.state.lock().unwrap().connections, before + 2);
    fake.with(|s| s.drop_after = Some(0));
    assert_eq!(w.stat(b"/f", false, &c).await.unwrap_err().name, ErrorName::ConnectionLost);
    fake.with(|s| s.drop_after = None);
    w.stat(b"/f", false, &c).await.unwrap();
    fake.with(|s| s.drop_after = Some(1));
    let e = w
        .upload(b"/g", &WriteOptions::default(), &mut Data(b"y".to_vec(), 0, true), &mut Moves::quiet(), &c)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
}

#[tokio::test]
async fn keep_alive_reuses_one_connection() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    let before = fake.state.lock().unwrap().connections;
    for _ in 0..3 {
        w.keep_alive(&c).await.unwrap();
        w.stat(b"/", false, &c).await.unwrap();
    }
    assert_eq!(fake.state.lock().unwrap().connections, before);
}

#[tokio::test]
async fn rate_limits_and_server_errors() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    fake.with(|s| {
        s.canned.push((
            Method::from_bytes(b"PROPFIND").unwrap(),
            StatusCode::TOO_MANY_REQUESTS,
            vec![("retry-after", "3")],
            "",
        ));
    });
    let e = w.stat(b"/", false, &c).await.unwrap_err();
    assert_eq!((e.name, e.retry_after_ms), (ErrorName::RateLimited, 3000));
    fake.with(|s| s.canned.push((Method::OPTIONS, StatusCode::INTERNAL_SERVER_ERROR, vec![], "boom")));
    assert_eq!(w.keep_alive(&c).await.unwrap_err().name, ErrorName::ProtocolError);
    w.keep_alive(&c).await.unwrap();
}

#[tokio::test]
async fn a_canceled_token_stops_calls() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    c.cancel();
    assert_eq!(w.stat(b"/", false, &c).await.unwrap_err().name, ErrorName::Canceled);
    assert_eq!(w.keep_alive(&c).await.unwrap_err().name, ErrorName::Canceled);
    assert!(fake.seen().is_empty());
    let mut fresh = Webdav::with_anchors(anchors());
    assert_eq!(fresh.connect(&params(&fake, &[]), &c).await.unwrap_err().name, ErrorName::Canceled);
}

#[tokio::test]
async fn disconnect_ends_the_connection() {
    let fake = server(Cert::Trusted).await;
    let mut w = signed_in(&fake, "").await;
    let c = CancelToken::new();
    w.disconnect().await;
    assert_eq!(w.capabilities(), Capabilities::default());
    assert_eq!(w.stat(b"/", false, &c).await.unwrap_err().name, ErrorName::Internal);
    w.connect(&params(&fake, &[]), &c).await.unwrap();
    w.disconnect().await;
    w.disconnect().await;
}

#[tokio::test]
async fn unreachable_servers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut w = Webdav::with_anchors(anchors());
    let p = Params { host: "127.0.0.1".into(), port: i32::from(port), ..Params::default() };
    assert_eq!(w.connect(&p, &CancelToken::new()).await.unwrap_err().name, ErrorName::NetworkUnreachable);
}
