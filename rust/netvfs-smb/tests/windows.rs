// SPDX-License-Identifier: LGPL-2.1-or-later
//! M-T11: netvfs-smb against Windows's own SMB server (the `windows-smb`
//! job of .github/workflows/ci.yml: a local account and a share on the
//! runner, reached over loopback, which is real SMB 3.1.1). The job sets
//! `NETVFS_INTEROP_SMB_WINDOWS` (the address), `..._USER`, `..._PASSWORD`
//! and `..._SHARE`; without them every test passes at once, saying so.
// A test crate: the helpers outside `#[test]` may panic, index and do plain
// arithmetic (clippy.toml relaxes that only inside `#[test]`), and the tests
// print what Windows chose.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

use std::time::Duration;

use netvfs_smb::auth::Account;
use netvfs_smb::backend::Smb;
use netvfs_smb::error::Error;
use netvfs_smb::profile::Profile;
use netvfs_smb::session::{self, Session};
use netvfs_smb::status::NtStatus;
use netvfs_smb::transport;
use netvfs_vfs::{
    Backend, CancelToken, Credentials, Disposition, Entry, ErrorName, ListOptions, ListSink, Params,
    Progress, RenameMode, Sink, Source, Status, Value, WriteOptions,
};
use zeroize::Zeroizing;

const T: Duration = Duration::from_secs(30);

struct Windows {
    host: String,
    user: String,
    password: String,
    share: String,
}

impl Windows {
    fn get() -> Option<Self> {
        let var = |name: &str| {
            std::env::var(format!("NETVFS_INTEROP_SMB_WINDOWS{name}")).ok().filter(|v| !v.is_empty())
        };
        if let (Some(host), Some(user), Some(password), Some(share)) =
            (var(""), var("_USER"), var("_PASSWORD"), var("_SHARE"))
        {
            Some(Self { host, user, password, share })
        } else {
            eprintln!("skipped: NETVFS_INTEROP_SMB_WINDOWS* not set (the windows-smb CI job sets them)");
            None
        }
    }

    fn account(&self, password: &str) -> Account {
        Account::User {
            user: self.user.clone(),
            domain: String::new(),
            password: Zeroizing::new(password.to_owned()),
        }
    }

    async fn sign_in(&self, profile: Profile, account: &Account) -> Result<Session, Error> {
        let addrs = transport::resolve(&self.host, 445).await?;
        let (stream, _) = transport::connect(&addrs, T).await?;
        session::sign_in(stream, profile, account, &self.host, T, &CancelToken::new()).await
    }

    async fn backend(&self, options: &[(&str, &str)]) -> Smb {
        let params = Params {
            provider: "smb".into(),
            host: self.host.clone(),
            username: self.user.clone(),
            options: options.iter().map(|(k, v)| ((*k).to_owned(), Value::Str((*v).to_owned()))).collect(),
            ..Params::default()
        };
        let credentials = Credentials {
            user: self.user.clone(),
            secret: Zeroizing::new(self.password.clone().into_bytes()),
            domain: String::new(),
        };
        let mut smb = Smb::new();
        smb.connect(&params, &CancelToken::new()).await.unwrap();
        smb.authenticate(&credentials, None, &CancelToken::new()).await.unwrap();
        smb
    }
}

#[derive(Default)]
struct Names(Vec<String>);

impl ListSink for Names {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend(batch.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()));
        true
    }
}

struct Bytes<'a>(&'a [u8]);

impl Source for Bytes<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }

    fn size(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

#[derive(Default)]
struct Collected(Vec<u8>);

impl Sink for Collected {
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

/// strict and signed: SMB 3.1.1; strict encrypts, signed signs (the share
/// does not ask for encryption).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profiles() {
    let Some(windows) = Windows::get() else { return };
    let account = windows.account(&windows.password);
    for profile in [Profile::Strict, Profile::Signed] {
        let s = windows.sign_in(profile, &account).await.unwrap();
        eprintln!(
            "{profile:?}: dialect 0x{:04x}, cipher {:?}, session flags 0x{:04x}, encrypting {}",
            s.negotiated.dialect,
            s.negotiated.cipher,
            s.flags,
            s.conn.encrypts()
        );
        assert_eq!(s.negotiated.dialect, 0x0311);
        assert!(s.negotiated.cipher.is_some());
        assert_eq!(s.conn.encrypts(), profile == Profile::Strict);
        let tree =
            session::tree_connect(&s.conn, &windows.host, &windows.share, &CancelToken::new()).await.unwrap();
        session::echo(&s.conn, &CancelToken::new()).await.unwrap();
        session::tree_disconnect(&s.conn, &tree, &CancelToken::new()).await.unwrap();
        s.conn.close(true).await;
    }
    let wrong = windows.account(&format!("{}x", windows.password));
    assert_eq!(
        windows.sign_in(Profile::Strict, &wrong).await.unwrap_err(),
        Error::Status(NtStatus::LOGON_FAILURE)
    );
}

/// Transfers and the namespace on the share, with the server's READ and
/// WRITE sizes (multi-credit).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_round_trip() {
    let Some(windows) = Windows::get() else { return };
    let mut smb = windows.backend(&[("share", &windows.share)]).await;
    let cancel = CancelToken::new();
    smb.make_dir(b"netvfs-rs", false, &cancel).await.unwrap();
    let content: Vec<u8> =
        (0..3 * 1024 * 1024 + 17_u32).map(|i| (i.wrapping_mul(131) >> 3).to_le_bytes()[0]).collect();
    let options = WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() };
    smb.upload(b"netvfs-rs/big.bin", &options, &mut Bytes(&content), &mut Quiet, &cancel).await.unwrap();
    let mut got = Collected::default();
    smb.download(b"netvfs-rs/big.bin", 0, None, &mut got, &mut Quiet, &cancel).await.unwrap();
    assert!(got.0 == content);
    smb.upload(b"netvfs-rs/small.bin", &options, &mut Bytes(b"small"), &mut Quiet, &cancel).await.unwrap();
    let e = smb
        .rename(b"netvfs-rs/small.bin", b"netvfs-rs/big.bin", RenameMode::NoReplace, &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    smb.rename(b"netvfs-rs/small.bin", b"netvfs-rs/big.bin", RenameMode::Replace, &cancel).await.unwrap();
    let mut names = Names::default();
    smb.list(b"netvfs-rs", ListOptions::default(), &mut names, &cancel).await.unwrap();
    assert_eq!(names.0, ["big.bin"]);
    assert_eq!(smb.stat(b"netvfs-rs/big.bin", true, &cancel).await.unwrap().size, Some(5));
    assert!(smb.space_info(b"netvfs-rs", &cancel).await.unwrap().total.unwrap() > 0);
    smb.remove_file(b"netvfs-rs/big.bin", &cancel).await.unwrap();
    smb.remove_dir(b"netvfs-rs", &cancel).await.unwrap();
    smb.disconnect().await;
}

/// Server mode: Windows's srvsvc lists the share (NetrShareEnum level 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_mode_lists_the_share() {
    let Some(windows) = Windows::get() else { return };
    let mut smb = windows.backend(&[]).await;
    let mut names = Names::default();
    smb.list(b"/", ListOptions::default(), &mut names, &CancelToken::new()).await.unwrap();
    eprintln!("shares: {:?}", names.0);
    assert!(names.0.iter().any(|n| n.eq_ignore_ascii_case(&windows.share)), "{:?}", names.0);
    assert!(!names.0.iter().any(|n| n.ends_with('$')), "{:?}", names.0);
    smb.disconnect().await;
}
