// SPDX-License-Identifier: LGPL-2.1-or-later
//! The account directory against netvfs-accounts-fake, a real process that
//! answers in the helper's format (the tst_BridgeAccounts directory cases).

#![allow(clippy::unwrap_used, clippy::unwrap_in_result, clippy::indexing_slicing)]

use netvfs_bridge::accounts::helper::HelperDirectory;
use netvfs_bridge::accounts::{AccountDirectory, Attention, Value};
use netvfs_bridge::testutil::TempDir;
use netvfs_bridge_proto::ErrorName;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const FAKE: &str = env!("CARGO_BIN_EXE_netvfs-accounts-fake");

const TABLE: &str = "# The fake's table\n\n\
                     account\t1\tsftp\tFiles at home\tfiles.example\t2222\talice\t/srv/a\t\n\
                     option\t1\tcompress\tb\ttrue\n\
                     option\t1\tdepth\ti\t-3\n\
                     option\t1\tkey-file\ts\t/k\n\
                     option\t1\tretries\ti\t-3\n\
                     option\t1\tretries\tu\t3\n\
                     account\t5\tsmb\tNAS\tnas.example\t0\tbob\t/\tauth-failed\n";

/// A directory over the fake helper with its table, through a wrapper
/// script that sets `NETVFS_FAKE_ACCOUNTS` (the directory passes on the
/// bridge's environment; tests run in parallel).
struct Fixture {
    dir: TempDir,
    table: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new(table: &str) -> Self {
        let dir = TempDir::new();
        let table = dir.write("accounts", table);
        let script = format!("#!/bin/sh\nNETVFS_FAKE_ACCOUNTS='{}' exec '{FAKE}' \"$@\"\n", table.display());
        let helper = dir.write("helper", script);
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir, table, helper }
    }

    fn directory(&self) -> HelperDirectory {
        HelperDirectory::new(&self.helper)
    }
}

#[tokio::test]
async fn directory_lists() {
    let fixture = Fixture::new(TABLE);
    let accounts = fixture.directory().list().await;
    assert_eq!(accounts.len(), 2);
    let home = &accounts[0];
    assert_eq!(
        (home.account_id, home.provider.as_str(), home.display_name.as_str()),
        (1, "sftp", "Files at home")
    );
    assert_eq!(
        (home.params.host.as_str(), home.params.port, home.params.username.as_str()),
        ("files.example", 2222, "alice")
    );
    assert_eq!(home.files_root, b"/srv/a");
    assert_eq!(home.params.provider, "sftp");
    assert_eq!(home.attention, Attention::None);
    assert_eq!(
        home.params.options,
        [
            ("compress".into(), Value::Bool(true)),
            ("depth".into(), Value::Int(-3)),
            ("key-file".into(), Value::String("/k".into())),
            ("retries".into(), Value::UInt(3)),
        ]
    );
    assert_eq!((accounts[1].account_id, accounts[1].attention), (5, Attention::AuthFailed));
}

#[tokio::test]
async fn directory_failures() {
    // A table the fake cannot read: the helper's failure, nothing listed.
    let fixture = Fixture::new("account\tbad\n");
    assert!(fixture.directory().list().await.is_empty());
    assert_eq!(fixture.directory().files(1).await.unwrap_err().name, ErrorName::Internal);
    assert!(HelperDirectory::new("/nonexistent/netvfs-accounts").list().await.is_empty());
}

#[tokio::test]
async fn directory_fetch_files() {
    let fixture = Fixture::new(TABLE);
    let directory = fixture.directory();
    let access = directory.files(5).await.unwrap();
    assert_eq!(
        (access.params.host.as_str(), access.credentials_id, access.secret_optional),
        ("nas.example", 0, true)
    );
    // An account the helper does not hand out.
    for id in [2, 0, -1] {
        let status = directory.files(id).await.unwrap_err();
        assert_eq!(status.to_string(), "NotFound: No such account");
    }
    let missing = HelperDirectory::new("/nonexistent/netvfs-accounts");
    assert_eq!(missing.files(1).await.unwrap_err().name, ErrorName::Unsupported);
}

#[tokio::test]
async fn directory_attention() {
    let fixture = Fixture::new(TABLE);
    let count = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&count);
    let directory = fixture.directory().on_change(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    directory.set_attention(1, Attention::ServerIdentityChanged, "SHA256:pin").await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(directory.list().await[0].attention, Attention::ServerIdentityChanged);
    let table = std::fs::read_to_string(&fixture.table).unwrap();
    assert!(table.ends_with("attention\t1\tserver-identity-changed\tSHA256:pin\n"), "{table}");

    // Refused writes are logged, and nothing changed.
    directory.set_attention(2, Attention::AuthFailed, "").await;
    directory.set_attention(1, Attention::None, "").await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read_to_string(&fixture.table).unwrap(), table);
    assert!(fixture.dir.path().exists());
}

/// The fake's own answer to `arguments`, decoded as a status (`Err`: its
/// text).
fn fake_status(table: &std::path::Path, arguments: &[&str]) -> Result<(), String> {
    let output =
        std::process::Command::new(FAKE).args(arguments).env("NETVFS_FAKE_ACCOUNTS", table).output().unwrap();
    assert!(output.status.success());
    netvfs_bridge::accounts::qds::decode_status(&output.stdout).map_err(|s| s.to_string())
}

#[test]
fn fake_commands() {
    let fixture = Fixture::new(&format!("{TABLE}account\t0\tsftp\tZero\th\t0\tu\t/\t\n"));
    let usage = Err(
        "Unsupported: Usage: netvfs-accounts list | files <id> | attention <id> <state> [pin]".to_owned()
    );
    for arguments in [
        &[][..],
        &["bogus"],
        &["list", "x"],
        &["bogus", "1"],
        &["bogus", "1", "auth-failed"],
        &["bogus", "1", "auth-failed", "pin"],
        &["attention", "1", "auth-failed", "pin", "x"],
    ] {
        assert_eq!(fake_status(&fixture.table, arguments), usage, "{arguments:?}");
    }
    assert_eq!(fake_status(&fixture.table, &["attention", "1", "auth-failed"]), Ok(()));
    assert_eq!(fake_status(&fixture.table, &["attention", "1", "server-identity-changed", "p"]), Ok(()));
    assert_eq!(
        fake_status(&fixture.table, &["attention", "1", "bogus"]),
        Err("Unsupported: Unknown attention state".into())
    );
    assert_eq!(
        fake_status(&fixture.table, &["attention", "0", "auth-failed"]),
        Err("NotFound: No such account".into())
    );
}
