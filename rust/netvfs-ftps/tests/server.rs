// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-ftps against a real FTPS server: proftpd in the container of tests/interop/ftps, which `run.sh` starts and
//! describes in `NETVFS_INTEROP_FTPS_*` (port, password). Without them every test passes at once, saying so. The
//! server's certificate is self-signed: the first connection reports its key, later ones pin it.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::unwrap_in_result
)]

use netvfs_ftps::backend::Ftps;
use netvfs_vfs::{
    Backend, CancelToken, Credentials, Disposition, Entry, EntryType, ErrorName, IdentityKind, ListOptions,
    ListSink, Params, Progress, RenameMode, Sink, Source, Status, Value, WriteOptions, Zeroizing,
};

struct Server {
    port: i32,
    password: String,
}

fn server() -> Option<Server> {
    let Ok(password) = std::env::var("NETVFS_INTEROP_FTPS_PASSWORD") else {
        eprintln!("skipped: NETVFS_INTEROP_FTPS_* not set (tests/interop/ftps/run.sh sets them)");
        return None;
    };
    let port = std::env::var("NETVFS_INTEROP_FTPS_PORT").ok().and_then(|p| p.parse().ok()).expect("a port");
    Some(Server { port, password })
}

impl Server {
    fn params(&self, pin: Option<&str>) -> Params {
        let mut p = Params {
            provider: "ftps".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: self.port,
            username: "alice".to_owned(),
            connect_timeout_ms: 20_000,
            request_timeout_ms: 30_000,
            ..Params::default()
        };
        if let Some(pin) = pin {
            p.options.insert("host_key".to_owned(), Value::Str(pin.to_owned()));
        }
        p
    }

    fn credentials(secret: &str) -> Credentials {
        Credentials {
            user: "alice".to_owned(),
            secret: Zeroizing::new(secret.as_bytes().to_vec()),
            ..Credentials::default()
        }
    }

    /// Signed in, pinned to the key the first connection reports.
    async fn signed_in(&self) -> Ftps {
        let c = CancelToken::new();
        let mut f = Ftps::new();
        let id =
            f.connect(&self.params(None), &c).await.unwrap().expect("a self-signed certificate is reported");
        assert_eq!(id.kind, IdentityKind::Tls);
        let pin = format!("{} {}", id.algorithm, data_encoding::BASE64.encode(&id.public_key));
        assert_eq!(
            f.connect(&self.params(Some(&pin)), &c).await.unwrap().map(|i| i.public_key),
            Some(id.public_key)
        );
        f.authenticate(&Self::credentials(&self.password), None, &c).await.unwrap();
        f
    }
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

#[tokio::test]
async fn a_wrong_password_is_refused() {
    let Some(s) = server() else { return };
    let c = CancelToken::new();
    let mut f = Ftps::new();
    f.connect(&s.params(None), &c).await.unwrap();
    let e = f.authenticate(&Server::credentials("wrong"), None, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AuthFailed);
}

#[tokio::test]
async fn files_and_folders_round_trip() {
    let Some(s) = server() else { return };
    let mut f = s.signed_in().await;
    let c = CancelToken::new();
    let dir = b"/round trip";
    f.make_dir(dir, false, &c).await.unwrap();
    f.make_dir(b"/round trip/inner", true, &c).await.unwrap();
    assert_eq!(f.make_dir(b"/round trip/inner", true, &c).await.unwrap_err().name, ErrorName::AlreadyExists);
    let body: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let o = WriteOptions { disposition: Disposition::CreateNew, ..WriteOptions::default() };
    f.upload(b"/round trip/a b.bin", &o, &mut Data(body.clone(), 0), &mut Quiet, &c).await.unwrap();
    let e = f.upload(b"/round trip/a b.bin", &o, &mut Data(vec![1], 0), &mut Quiet, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    let st = f.stat(b"/round trip/a b.bin", true, &c).await.unwrap();
    assert_eq!((st.kind, st.size), (EntryType::File, Some(3_000_000)));
    assert!(st.mtime_ms.is_some());
    let mut list = Collect::default();
    f.list(dir, ListOptions::default(), &mut list, &c).await.unwrap();
    let mut names: Vec<_> =
        list.0.iter().map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.kind)).collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(names, [("a b.bin".to_owned(), EntryType::File), ("inner".to_owned(), EntryType::Directory)]);
    let mut out = Out::default();
    f.download(b"/round trip/a b.bin", 0, None, &mut out, &mut Quiet, &c).await.unwrap();
    assert!(out.0 == body);
    let mut part = Out::default();
    f.download(b"/round trip/a b.bin", 1000, Some(500), &mut part, &mut Quiet, &c).await.unwrap();
    assert!(part.0 == body[1000..1500]);
    // The connection is in step after the cut-off read.
    f.rename(b"/round trip/a b.bin", b"/round trip/inner/c.bin", RenameMode::NoReplace, &c).await.unwrap();
    assert_eq!(f.stat(b"/round trip/a b.bin", true, &c).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(f.remove_dir(b"/round trip/inner", &c).await.unwrap_err().name, ErrorName::DirectoryNotEmpty);
    f.remove_file(b"/round trip/inner/c.bin", &c).await.unwrap();
    f.remove_dir(b"/round trip/inner", &c).await.unwrap();
    f.remove_dir(dir, &c).await.unwrap();
    let e = f.list(b"/no such", ListOptions::default(), &mut list, &c).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound, "{e:?}");
    f.keep_alive(&c).await.unwrap();
    f.disconnect().await;
}
