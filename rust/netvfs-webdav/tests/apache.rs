// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-webdav against Apache httpd mod_dav: the container of tests/interop/webdav, which `run.sh` starts and
//! describes in `NETVFS_INTEROP_WEBDAV_*` (password, ports, work folder with the certificates). Without them every
//! test passes at once, saying so. Tests run in parallel, each in folders of its own.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names
)]

use netvfs_tls::Anchors;
use netvfs_vfs::{
    Backend, CancelToken, Credentials, Disposition, Entry, EntryType, ErrorName, IdentityKind, ListOptions,
    ListSink, Params, Progress, ReadHandle, RenameMode, Sink, Source, Status, Value, WriteOptions, Zeroizing,
};
use netvfs_webdav::backend::Webdav;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

struct Server {
    password: String,
    work: String,
}

fn server() -> Option<Server> {
    let Ok(password) = std::env::var("NETVFS_INTEROP_WEBDAV_PASSWORD") else {
        eprintln!("skipped: NETVFS_INTEROP_WEBDAV_* not set (tests/interop/webdav/run.sh sets them)");
        return None;
    };
    Some(Server { password, work: std::env::var("NETVFS_INTEROP_WEBDAV_WORK").expect("the work folder") })
}

impl Server {
    fn port(name: &str) -> i32 {
        let var = format!("NETVFS_INTEROP_WEBDAV_{name}");
        std::env::var(&var).ok().and_then(|p| p.parse().ok()).unwrap_or_else(|| panic!("{var} is not a port"))
    }

    fn params(port: &str, host: &str, base: &str, pin: Option<&str>) -> Params {
        let mut p = Params {
            provider: "webdav".to_owned(),
            host: host.to_owned(),
            port: Self::port(port),
            username: "alice".to_owned(),
            connect_timeout_ms: 20_000,
            request_timeout_ms: 30_000,
            ..Params::default()
        };
        p.options.insert("base_path".to_owned(), Value::Str(base.to_owned()));
        if let Some(pin) = pin {
            p.options.insert("host_key".to_owned(), Value::Str(pin.to_owned()));
        }
        p
    }

    fn credentials(&self, secret: &str) -> Credentials {
        let secret = if secret.is_empty() { self.password.clone() } else { secret.to_owned() };
        Credentials {
            user: "alice".to_owned(),
            secret: Zeroizing::new(secret.into_bytes()),
            ..Credentials::default()
        }
    }

    /// The run's test CA as the only trusted authority.
    fn anchors(&self) -> Anchors {
        let der = std::fs::read(format!("{}/certs/ca.der", self.work)).expect("the CA certificate");
        let mut store = RootCertStore::empty();
        store.add(CertificateDer::from(der)).unwrap();
        Anchors::Custom(Arc::new(store))
    }

    /// The pin of the self-signed server, as its first connection reports it.
    async fn pin(&self) -> String {
        let mut w = Webdav::with_anchors(self.anchors());
        let id = w
            .connect(&Self::params("SELF", "127.0.0.1", "/dav", None), &c())
            .await
            .unwrap()
            .expect("an identity");
        format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(&id.public_key))
    }

    /// Signed in on the self-signed server, pinned, at `/dav`.
    async fn signed_in(&self) -> Webdav {
        let pin = self.pin().await;
        let mut w = Webdav::with_anchors(self.anchors());
        assert_eq!(
            w.connect(&Self::params("SELF", "127.0.0.1", "/dav", Some(&pin)), &c())
                .await
                .unwrap()
                .map(|i| i.kind),
            Some(IdentityKind::Tls)
        );
        w.authenticate(&self.credentials(""), None, &c()).await.unwrap();
        w
    }

    fn on_disk(&self, path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/dav/{path}", self.work)).expect("the file on the server")
    }
}

fn c() -> CancelToken {
    CancelToken::new()
}

/// A folder name no other test (or earlier run) uses.
fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    format!("{prefix} {nanos} {}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[derive(Default)]
struct Collect(Vec<Entry>);

impl ListSink for Collect {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        true
    }
}

struct Data(Vec<u8>, usize);

impl Source for Data {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
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

struct Quiet;

impl Progress for Quiet {
    fn update(&mut self, _: u64, _: Option<u64>) {}
    fn canceled(&mut self) -> bool {
        false
    }
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap()).collect()
}

async fn put(w: &mut Webdav, path: &str, bytes: &[u8], disposition: Disposition) -> Result<(), Status> {
    let options =
        WriteOptions { disposition, expected_size: Some(bytes.len() as u64), ..WriteOptions::default() };
    w.upload(path.as_bytes(), &options, &mut Data(bytes.to_vec(), 0), &mut Quiet, &c()).await
}

async fn get(w: &mut Webdav, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>, Status> {
    let mut out = Out::default();
    w.download(path.as_bytes(), offset, length, &mut out, &mut Quiet, &c()).await?;
    Ok(out.0)
}

async fn names(w: &mut Webdav, dir: &str) -> Vec<(String, EntryType, Option<u64>)> {
    let mut sink = Collect::default();
    w.list(dir.as_bytes(), ListOptions::default(), &mut sink, &c()).await.unwrap();
    let mut out: Vec<_> =
        sink.0.into_iter().map(|e| (String::from_utf8(e.name).unwrap(), e.kind, e.size)).collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[tokio::test]
async fn a_self_signed_certificate_signs_in_only_when_pinned() {
    let Some(s) = server() else { return };
    let mut w = Webdav::with_anchors(s.anchors());
    let id = w.connect(&Server::params("SELF", "127.0.0.1", "/dav", None), &c()).await.unwrap().unwrap();
    assert_eq!((id.kind, id.algorithm.as_str()), (IdentityKind::Tls, "tls-spki-sha256"));
    assert!(id.fingerprint.starts_with("SHA256:"), "{}", id.fingerprint);

    // Another key as the pin: no credentials go out.
    let other = format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(b"another key"));
    let mut w = Webdav::with_anchors(s.anchors());
    w.connect(&Server::params("SELF", "127.0.0.1", "/dav", Some(&other)), &c()).await.unwrap();
    let e = w.authenticate(&s.credentials(""), None, &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ServerIdentityChanged, "{e:?}");

    let mut w = s.signed_in().await;
    w.keep_alive(&c()).await.unwrap();
    w.disconnect().await;
}

#[tokio::test]
async fn a_certificate_of_a_trusted_authority_needs_no_pin_and_h2_is_not_used() {
    let Some(s) = server() else { return };
    let mut w = Webdav::with_anchors(s.anchors());
    assert_eq!(w.connect(&Server::params("SIGNED", "localhost", "/dav", None), &c()).await.unwrap(), None);
    w.authenticate(&s.credentials(""), None, &c()).await.unwrap();
    let dir = unique("trusted");
    w.make_dir(dir.as_bytes(), true, &c()).await.unwrap();
    assert_eq!(w.stat(dir.as_bytes(), true, &c()).await.unwrap().kind, EntryType::Directory);
    w.remove_dir(dir.as_bytes(), &c()).await.unwrap();
    // The same server under an address its certificate does not name: a key to confirm.
    let mut w = Webdav::with_anchors(s.anchors());
    let id = w.connect(&Server::params("SIGNED", "127.0.0.1", "/dav", None), &c()).await.unwrap();
    assert_eq!(id.map(|i| i.kind), Some(IdentityKind::Tls));
}

#[tokio::test]
async fn tls_1_2_is_refused() {
    let Some(s) = server() else { return };
    let mut w = Webdav::with_anchors(s.anchors());
    let e = w.connect(&Server::params("TLS12", "127.0.0.1", "/dav", None), &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy, "{e:?}");
}

#[tokio::test]
async fn wrong_passwords_redirects_and_missing_folders() {
    let Some(s) = server() else { return };
    let pin = s.pin().await;
    let mut w = Webdav::with_anchors(s.anchors());
    w.connect(&Server::params("SELF", "127.0.0.1", "/dav", Some(&pin)), &c()).await.unwrap();
    let e = w.authenticate(&s.credentials("wrong"), None, &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AuthFailed, "{e:?}");

    for (base, name) in [("/moved", ErrorName::ProtocolError), ("/dav/no such folder", ErrorName::NotFound)] {
        let mut w = Webdav::with_anchors(s.anchors());
        w.connect(&Server::params("SELF", "127.0.0.1", base, Some(&pin)), &c()).await.unwrap();
        let e = w.authenticate(&s.credentials(""), None, &c()).await.unwrap_err();
        assert_eq!(e.name, name, "{base}: {e:?}");
    }
}

#[tokio::test]
async fn files_and_folders_round_trip() {
    let Some(s) = server() else { return };
    let mut w = s.signed_in().await;
    let dir = unique("round trip ä%#?");
    let bytes = data(3_000_000);
    w.make_dir(dir.as_bytes(), true, &c()).await.unwrap();
    assert_eq!(w.make_dir(dir.as_bytes(), true, &c()).await.unwrap_err().name, ErrorName::AlreadyExists);
    w.make_dir(dir.as_bytes(), false, &c()).await.unwrap();
    let f = format!("{dir}/f.bin");
    put(&mut w, &f, &bytes, Disposition::CreateNew).await.unwrap();
    assert_eq!(s.on_disk(&f), bytes);
    assert_eq!(
        put(&mut w, &f, b"x", Disposition::CreateNew).await.unwrap_err().name,
        ErrorName::AlreadyExists
    );
    assert_eq!(s.on_disk(&f), bytes);

    let entry = w.stat(f.as_bytes(), true, &c()).await.unwrap();
    assert_eq!((entry.kind, entry.size), (EntryType::File, Some(3_000_000)));
    assert!(entry.mtime_ms.is_some() && !entry.etag.is_empty());
    assert_eq!(get(&mut w, &f, 0, None).await.unwrap(), bytes);
    assert_eq!(get(&mut w, &f, 1000, Some(500)).await.unwrap(), bytes[1000..1500]);
    assert_eq!(get(&mut w, &f, 3_000_000, None).await.unwrap(), b"");
    let mut handle = w.open_read(f.as_bytes(), &c()).await.unwrap();
    let mut buf = [0; 100];
    assert_eq!(handle.read(2_999_990, &mut buf, &c()).await.unwrap(), 10);
    assert_eq!(buf[..10], bytes[2_999_990..]);
    handle.close(&c()).await.unwrap();

    // Renames and copies: no replacing unless asked.
    let g = format!("{dir}/g.bin");
    put(&mut w, &g, b"small", Disposition::Truncate).await.unwrap();
    let e = w.rename(g.as_bytes(), f.as_bytes(), RenameMode::NoReplace, &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    w.copy(f.as_bytes(), g.as_bytes(), false, RenameMode::Replace, &c()).await.unwrap();
    assert_eq!(s.on_disk(&g), bytes);
    w.make_dir(format!("{dir}/sub").as_bytes(), true, &c()).await.unwrap();
    w.rename(g.as_bytes(), format!("{dir}/sub/h.bin").as_bytes(), RenameMode::NoReplace, &c()).await.unwrap();
    let tree = format!("{dir} copy");
    w.copy(dir.as_bytes(), tree.as_bytes(), true, RenameMode::NoReplace, &c()).await.unwrap();
    assert_eq!(
        names(&mut w, &tree).await,
        [
            ("f.bin".to_owned(), EntryType::File, Some(3_000_000)),
            ("sub".to_owned(), EntryType::Directory, None)
        ]
    );
    assert_eq!(s.on_disk(&format!("{tree}/sub/h.bin")), bytes);

    // Removing: a folder is not a file, a full folder is not removed.
    assert_eq!(w.remove_file(dir.as_bytes(), &c()).await.unwrap_err().name, ErrorName::IsADirectory);
    assert_eq!(w.remove_dir(dir.as_bytes(), &c()).await.unwrap_err().name, ErrorName::DirectoryNotEmpty);
    assert_eq!(w.stat(b"nothing here", true, &c()).await.unwrap_err().name, ErrorName::NotFound);
    for d in [&dir, &tree] {
        w.remove_file(format!("{d}/sub/h.bin").as_bytes(), &c()).await.unwrap();
        w.remove_dir(format!("{d}/sub").as_bytes(), &c()).await.unwrap();
        w.remove_file(format!("{d}/f.bin").as_bytes(), &c()).await.unwrap();
        w.remove_dir(d.as_bytes(), &c()).await.unwrap();
    }
    assert!(!names(&mut w, "").await.iter().any(|(n, ..)| n == &dir));
}

#[tokio::test]
async fn a_full_server_is_no_space_and_leaves_no_file() {
    let Some(s) = server() else { return };
    let pin = s.pin().await;
    let mut w = Webdav::with_anchors(s.anchors());
    w.connect(&Server::params("SELF", "127.0.0.1", "/small", Some(&pin)), &c()).await.unwrap();
    w.authenticate(&s.credentials(""), None, &c()).await.unwrap();
    let f = unique("big");
    let e = put(&mut w, &f, &data(2 << 20), Disposition::Truncate).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NoSpace, "{e:?}");
    assert_eq!(w.stat(f.as_bytes(), true, &c()).await.unwrap_err().name, ErrorName::NotFound);
}
