// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr
)]

use netvfs_tls::Anchors;
use netvfs_vfs::{
    Backend, CancelToken, Capability, Credentials, Disposition, Entry, EntryType, ListSink, Params, Progress,
    Source, Status, Value, WriteOptions, Zeroizing,
};
use netvfs_webdav::backend::Webdav;
use rustls::RootCertStore;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const HOME: &str = "/remote.php/dav/files/alice";

struct Server {
    port: i32,
    password: String,
}

fn server() -> Option<Server> {
    let Ok(password) = std::env::var("NETVFS_INTEROP_NEXTCLOUD_PASSWORD") else {
        eprintln!("skipped: NETVFS_INTEROP_NEXTCLOUD_* not set (tests/interop/nextcloud/run.sh sets them)");
        return None;
    };
    let port = std::env::var("NETVFS_INTEROP_NEXTCLOUD_PORT").ok().and_then(|p| p.parse().ok());
    Some(Server {
        port: port.unwrap_or_else(|| panic!("NETVFS_INTEROP_NEXTCLOUD_PORT is not a port")),
        password,
    })
}

impl Server {
    fn params(&self, base: &str, pin: Option<&str>) -> Params {
        let mut p = Params {
            provider: "webdav".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: self.port,
            username: "alice".to_owned(),
            connect_timeout_ms: 20_000,
            request_timeout_ms: 60_000,
            ..Params::default()
        };
        p.options.insert("base_path".to_owned(), Value::Str(base.to_owned()));
        if let Some(pin) = pin {
            p.options.insert("host_key".to_owned(), Value::Str(pin.to_owned()));
        }
        p
    }

    async fn signed_in(&self, base: &str) -> Webdav {
        let anchors = || Anchors::Custom(Arc::new(RootCertStore::empty()));
        let mut w = Webdav::with_anchors(anchors());
        let id = w.connect(&self.params(base, None), &c()).await.unwrap().expect("an identity");
        let pin = format!("tls-spki-sha256 {}", data_encoding::BASE64.encode(&id.public_key));
        let mut w = Webdav::with_anchors(anchors());
        w.connect(&self.params(base, Some(&pin)), &c()).await.unwrap();
        let credentials = Credentials {
            user: "alice".to_owned(),
            secret: Zeroizing::new(self.password.clone().into_bytes()),
            ..Credentials::default()
        };
        w.authenticate(&credentials, None, &c()).await.unwrap();
        w
    }
}

fn c() -> CancelToken {
    CancelToken::new()
}

fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    format!("{prefix}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed))
}

#[derive(Default)]
struct Collect(Vec<Entry>);

impl ListSink for Collect {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        true
    }
}

struct OneByte(bool);

impl Source for OneByte {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        if self.0 || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = b'x';
        self.0 = true;
        Ok(1)
    }
    fn size(&self) -> Option<u64> {
        Some(1)
    }
}

struct Quiet;

impl Progress for Quiet {
    fn update(&mut self, _: u64, _: Option<u64>) {}
    fn canceled(&mut self) -> bool {
        false
    }
}

async fn folders(w: &mut Webdav, paths: &[String]) {
    for path in paths {
        w.make_dir(path.as_bytes(), true, &c()).await.unwrap();
    }
}

async fn file(w: &mut Webdav, path: &str) {
    let options = WriteOptions {
        disposition: Disposition::CreateNew,
        expected_size: Some(1),
        ..WriteOptions::default()
    };
    w.upload(path.as_bytes(), &options, &mut OneByte(false), &mut Quiet, &c()).await.unwrap();
}

async fn etag(w: &mut Webdav, path: &str) -> Vec<u8> {
    let etag = w.stat(path.as_bytes(), false, &c()).await.unwrap().etag;
    assert!(!etag.is_empty(), "{path} has an etag");
    etag
}

async fn found(w: &mut Webdav, root: &str, text: &str, limit: u32) -> Vec<Entry> {
    let mut sink = Collect::default();
    w.search(root.as_bytes(), text, limit, &mut sink, &c()).await.unwrap();
    sink.0.sort_by(|a, b| a.name.cmp(&b.name));
    sink.0
}

async fn names(w: &mut Webdav, root: &str, text: &str) -> Vec<String> {
    found(w, root, text, 100).await.into_iter().map(|e| String::from_utf8(e.name).unwrap()).collect()
}

#[tokio::test]
async fn sign_in_reports_deep_etags_and_search() {
    let Some(s) = server() else { return };
    let mut w = s.signed_in(HOME).await;
    let caps = w.capabilities();
    assert!(caps.has(Capability::DeepETags) && caps.has(Capability::Search), "{:?}", caps.names());
    let sub = unique("caps");
    folders(&mut w, std::slice::from_ref(&sub)).await;
    let below = s.signed_in(&format!("{HOME}/{sub}")).await.capabilities();
    assert!(below.has(Capability::DeepETags) && below.has(Capability::Search), "{:?}", below.names());
}

#[tokio::test]
async fn a_file_added_below_changes_the_etags_above_it_and_no_other() {
    let Some(s) = server() else { return };
    let mut w = s.signed_in(HOME).await;
    let top = unique("etags");
    let (a, b, other) = (format!("{top}/a"), format!("{top}/a/b"), format!("{top}/other"));
    folders(&mut w, &[top.clone(), a.clone(), b.clone(), other.clone()]).await;
    let before = (etag(&mut w, &top).await, etag(&mut w, &a).await, etag(&mut w, &other).await);
    file(&mut w, &format!("{b}/new.txt")).await;
    let after = (etag(&mut w, &top).await, etag(&mut w, &a).await, etag(&mut w, &other).await);
    assert_ne!(before.0, after.0, "the top folder");
    assert_ne!(before.1, after.1, "the folder between");
    assert_eq!(before.2, after.2, "a sibling");
}

#[tokio::test]
async fn search_finds_names_below_the_folder_asked() {
    let Some(s) = server() else { return };
    let mut w = s.signed_in(HOME).await;
    let top = unique("search");
    let (a, b, other) = (format!("{top}/a"), format!("{top}/a/b"), format!("{top}/other"));
    folders(&mut w, &[top.clone(), a.clone(), b, other, format!("{top}/a/Lakeside album")]).await;
    file(&mut w, &format!("{top}/a/b/Lakeside 100%_sunset.txt")).await;
    file(&mut w, &format!("{top}/other/lakeside elsewhere.txt")).await;

    assert_eq!(
        names(&mut w, &top, "lakeside").await,
        ["a/Lakeside album", "a/b/Lakeside 100%_sunset.txt", "other/lakeside elsewhere.txt"],
        "files and folders, any case, paths below the folder asked"
    );
    assert_eq!(names(&mut w, &a, "lakeside").await, ["Lakeside album", "b/Lakeside 100%_sunset.txt"]);
    assert_eq!(names(&mut w, &top, "100%_").await, ["a/b/Lakeside 100%_sunset.txt"]);
    assert!(names(&mut w, &top, "1_0").await.is_empty(), "an underscore matches itself only");
    assert!(names(&mut w, &top, "0%s").await.is_empty(), "a percent sign matches itself only");
    assert!(names(&mut w, &top, "no such name").await.is_empty());
    assert_eq!(found(&mut w, &top, "lakeside", 1).await.len(), 1, "the limit");

    let hits = found(&mut w, &top, "lakeside", 100).await;
    assert_eq!(hits[0].kind, EntryType::Directory);
    let sunset = &hits[1];
    assert_eq!((sunset.kind, sunset.size), (EntryType::File, Some(1)));
    assert!(sunset.mtime_ms.is_some() && !sunset.etag.is_empty(), "{sunset:?}");
}

#[tokio::test]
async fn an_account_on_a_subfolder_searches_below_itself() {
    let Some(s) = server() else { return };
    let mut w = s.signed_in(HOME).await;
    let top = unique("sub");
    folders(&mut w, &[top.clone(), format!("{top}/in"), format!("{top}/in/deep"), format!("{top}/out")])
        .await;
    file(&mut w, &format!("{top}/in/deep/harbour.txt")).await;
    file(&mut w, &format!("{top}/out/harbour.txt")).await;
    let mut sub = s.signed_in(&format!("{HOME}/{top}/in")).await;
    assert_eq!(names(&mut sub, "", "harbour").await, ["deep/harbour.txt"]);
    assert_eq!(names(&mut sub, "deep", "harbour").await, ["harbour.txt"]);
}
