// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use crate::testserver::{Proxy, Script, Server, Subsystem};
use netvfs_vfs::{Capability, Disposition, EntryType, ReadHandle, Value, WriteHandle};
use std::net::SocketAddr;

fn params(addr: SocketAddr) -> Params {
    Params {
        provider: "sftp".to_owned(),
        host: addr.ip().to_string(),
        port: i32::from(addr.port()),
        username: "alice".to_owned(),
        connect_timeout_ms: 10_000,
        request_timeout_ms: 10_000,
        ..Params::default()
    }
}

fn with_option(mut p: Params, key: &str, value: &str) -> Params {
    p.options.insert(key.to_owned(), Value::Str(value.to_owned()));
    p
}

fn password(secret: &[u8]) -> Credentials {
    Credentials { secret: Zeroizing::new(secret.to_vec()), ..Credentials::default() }
}

use zeroize::Zeroizing;

fn c() -> CancelToken {
    CancelToken::new()
}

async fn signed_in(server: &Server) -> Sftp {
    let mut sftp = Sftp::new();
    sftp.connect(&params(server.addr), &c()).await.unwrap();
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
    sftp
}

fn fresh() -> Status {
    Status::internal("authenticate() needs a fresh connection")
}

#[derive(Default)]
struct Collect(Vec<u8>);
impl Sink for Collect {
    fn write(&mut self, data: &[u8]) -> Result<(), Status> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

struct Bytes(&'static [u8], usize);
impl Source for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        let rest = &self.0[self.1..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.1 = self.1.saturating_add(n);
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.0.len().saturating_sub(self.1) as u64)
    }
}

struct Quiet;
impl Progress for Quiet {
    fn update(&mut self, _: u64, _: Option<u64>) {}
    fn canceled(&mut self) -> bool {
        false
    }
}

#[derive(Default)]
struct Names(Vec<Vec<u8>>);
impl ListSink for Names {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend(batch.iter().map(|e| e.name.clone()));
        true
    }
}

#[test]
fn settings_from_params() {
    let addr: SocketAddr = "127.0.0.1:2222".parse().unwrap();
    let s = Settings::of(&params(addr)).unwrap();
    assert_eq!(s.target.host, "127.0.0.1");
    assert_eq!(s.target.port, 2222);
    assert_eq!(
        (s.target.connect_timeout, s.request_timeout),
        (Duration::from_secs(10), Duration::from_secs(10))
    );
    assert_eq!((s.username.as_str(), s.auth_mode.as_deref(), s.pin.as_deref()), ("alice", None, None));
    assert_eq!((s.dir_mode, s.target.pinned_type.as_deref()), (DEFAULT_DIR_MODE, None));
    // Defaults (C-14, S-1).
    let p = Params { port: 0, connect_timeout_ms: 0, request_timeout_ms: -5, ..params(addr) };
    let s = Settings::of(&p).unwrap();
    assert_eq!(s.target.port, 22);
    assert_eq!(s.target.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    assert_eq!(s.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    assert_eq!((DEFAULT_CONNECT_TIMEOUT.as_millis(), DEFAULT_REQUEST_TIMEOUT.as_millis()), (15_000, 60_000));
    assert_eq!(Settings::of(&Params { port: -1, ..params(addr) }).unwrap().target.port, 22);
    assert_eq!(Settings::of(&Params { port: 1, ..params(addr) }).unwrap().target.port, 1);
    assert_eq!(Settings::of(&Params { port: 65535, ..params(addr) }).unwrap().target.port, 65535);
    assert_eq!(
        Settings::of(&Params { port: 65536, ..params(addr) }),
        Err(Status::internal("Invalid port 65536"))
    );
    let p = Params { connect_timeout_ms: 1, request_timeout_ms: 2, ..params(addr) };
    let s = Settings::of(&p).unwrap();
    assert_eq!(
        (s.target.connect_timeout, s.request_timeout),
        (Duration::from_millis(1), Duration::from_millis(2))
    );
    for host in ["", "alice@example.org", "@"] {
        let p = Params { host: host.to_owned(), ..params(addr) };
        assert_eq!(Settings::of(&p), Err(Status::internal("Invalid server name")), "{host}");
    }
    // Options.
    for (value, mode) in [
        ("750", 0o750),
        ("0700", 0o700),
        ("7777", 0o7777),
        ("0", 0),
        ("17777", 0o777),
        ("8", 0o777),
        ("x", 0o777),
        ("", 0o777),
    ] {
        assert_eq!(
            Settings::of(&with_option(params(addr), "dir_mode", value)).unwrap().dir_mode,
            mode,
            "{value}"
        );
    }
    let s = Settings::of(&with_option(params(addr), "auth_mode", "publickey")).unwrap();
    assert_eq!(s.auth_mode.as_deref(), Some("publickey"));
    let s = Settings::of(&with_option(params(addr), "host_key", "ssh-ed25519 AAAA")).unwrap();
    assert_eq!(
        (s.pin.as_deref(), s.target.pinned_type.as_deref()),
        (Some("ssh-ed25519 AAAA"), Some("ssh-ed25519"))
    );
    // A pin that cannot be read narrows nothing but stays a pin.
    let s = Settings::of(&with_option(params(addr), "host_key", "garbage")).unwrap();
    assert_eq!((s.pin.as_deref(), s.target.pinned_type), (Some("garbage"), None));
    let s = Settings::of(&with_option(params(addr), "host_key", "")).unwrap();
    assert_eq!(s.pin, None);
}

#[test]
fn pins() {
    assert_eq!(parse_pin("ssh-ed25519 AAAA"), Some(("ssh-ed25519".to_owned(), vec![0, 0, 0])));
    assert_eq!(parse_pin("  ssh-ed25519   AAAA \n"), Some(("ssh-ed25519".to_owned(), vec![0, 0, 0])));
    assert_eq!(parse_pin("ssh-rsa AQ=="), Some(("ssh-rsa".to_owned(), vec![1])));
    for bad in [
        "",
        "ssh-ed25519",
        "ssh-ed25519 AAAA extra",
        "ssh-ed25519 AQ",
        "ssh-ed25519 AR==",
        "a !!!!",
        "a ====",
    ] {
        assert_eq!(parse_pin(bad), None, "{bad}");
    }
    let addr: SocketAddr = "127.0.0.1:22".parse().unwrap();
    let identity = ServerIdentity {
        algorithm: "ssh-ed25519".to_owned(),
        public_key: vec![0, 0, 0],
        fingerprint: "f".to_owned(),
    };
    let settings = |pin: &str| Settings::of(&with_option(params(addr), "host_key", pin)).unwrap();
    assert!(!Settings::of(&params(addr)).unwrap().mismatch(&identity));
    assert!(!settings("ssh-ed25519 AAAA").mismatch(&identity));
    assert!(settings("ssh-ed25519 AAAB").mismatch(&identity));
    assert!(settings("ecdsa-sha2-nistp256 AAAA").mismatch(&identity));
    assert!(settings("garbage").mismatch(&identity));
}

#[tokio::test]
async fn connect_sign_in_and_work() {
    let server = Server::start(Script::password()).await;
    let mut sftp = Sftp::new();
    assert_eq!(sftp.capabilities(), Capabilities::default());
    let identity = sftp.connect(&params(server.addr), &c()).await.unwrap().unwrap();
    assert_eq!(identity, session::identity_of(&server.keys[0]));
    assert_eq!(sftp.capabilities(), Capabilities::default());
    assert_eq!(server.take_log(), Vec::<String>::new());
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
    assert_eq!(server.take_log(), ["none alice", "password alice secret", "session", "subsystem sftp"]);
    let caps = sftp.capabilities();
    for cap in [
        Capability::ReadHandles,
        Capability::EfficientRanges,
        Capability::WriteResume,
        Capability::PosixModes,
        Capability::SetModified,
        Capability::SetModifiedOnUpload,
        Capability::Symlinks,
        Capability::Hardlinks,
        Capability::Ownership,
        Capability::SpaceInfo,
        Capability::AtomicReplace,
        Capability::NativeNoReplace,
        Capability::ServerCopy,
    ] {
        assert!(caps.has(cap), "{cap:?}");
    }
    assert!(!caps.has(Capability::Checksums) && !caps.has(Capability::ServerCopyRecursive));
    // Relative paths are relative to the start folder (S-19).
    assert_eq!(sftp.stat(b"", true, &c()).await.unwrap().kind, EntryType::Directory);
    sftp.make_dir(b"Backups", true, &c()).await.unwrap();
    let options = WriteOptions { disposition: Disposition::CreateNew, ..WriteOptions::default() };
    sftp.upload(b"Backups/a.tar", &options, &mut Bytes(b"archive", 0), &mut Quiet, &c()).await.unwrap();
    assert_eq!(server.fake.data("/home/u/Backups/a.tar").unwrap(), b"archive");
    let mut sink = Collect::default();
    sftp.download(b"Backups/a.tar", 2, Some(3), &mut sink, &mut Quiet, &c()).await.unwrap();
    assert_eq!(sink.0, b"chi");
    let mut names = Names::default();
    sftp.list(b"Backups", ListOptions::default(), &mut names, &c()).await.unwrap();
    assert_eq!(names.0, [b"a.tar".to_vec()]);
    sftp.rename(b"Backups/a.tar", b"Backups/b.tar", RenameMode::NoReplace, &c()).await.unwrap();
    sftp.copy(b"Backups/b.tar", b"Backups/c.tar", false, RenameMode::NoReplace, &c()).await.unwrap();
    assert_eq!(server.fake.data("/home/u/Backups/c.tar").unwrap(), b"archive");
    let changes = Attributes { mode: Some(0o600), ..Attributes::default() };
    sftp.set_attributes(b"Backups/c.tar", &changes, &c()).await.unwrap();
    assert_eq!(sftp.stat(b"Backups/c.tar", false, &c()).await.unwrap().mode.map(|m| m & 0o7777), Some(0o600));
    sftp.make_symlink(b"c.tar", b"Backups/l", &c()).await.unwrap();
    assert_eq!(sftp.read_link(b"Backups/l", &c()).await.unwrap(), b"c.tar");
    sftp.make_hardlink(b"Backups/c.tar", b"Backups/h", &c()).await.unwrap();
    assert!(sftp.space_info(b"", &c()).await.unwrap().free.is_some());
    // Handles.
    let mut w = sftp.open_write(b"Backups/d", &options, &c()).await.unwrap();
    w.write(b"handle", &c()).await.unwrap();
    assert_eq!(w.position(), 6);
    w.commit(&c()).await.unwrap();
    let mut r = sftp.open_read(b"Backups/d", &c()).await.unwrap();
    assert_eq!(r.size(), Some(6));
    let mut buf = [0; 16];
    assert_eq!(r.read(1, &mut buf, &c()).await.unwrap(), 5);
    assert_eq!(&buf[..5], b"andle");
    r.close(&c()).await.unwrap();
    for f in ["b.tar", "c.tar", "l", "h", "d"] {
        sftp.remove_file(format!("Backups/{f}").as_bytes(), &c()).await.unwrap();
    }
    sftp.remove_dir(b"Backups", &c()).await.unwrap();
    assert_eq!(server.fake.node("/home/u/Backups"), None);
    sftp.keep_alive(&c()).await.unwrap();
    // A second sign-in on the same connection is refused, and leaves it be.
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
    sftp.keep_alive(&c()).await.unwrap();
    sftp.disconnect().await;
    assert_eq!(sftp.keep_alive(&c()).await, Err(not_signed_in()));
    assert_eq!(sftp.capabilities(), Capabilities::default());
}

#[tokio::test]
async fn nothing_works_before_sign_in() {
    let server = Server::start(Script::password()).await;
    let mut sftp = Sftp::new();
    for connected in [false, true] {
        if connected {
            sftp.connect(&params(server.addr), &c()).await.unwrap();
        }
        let n = Err(not_signed_in());
        assert_eq!(sftp.keep_alive(&c()).await, n);
        assert_eq!(sftp.stat(b"x", true, &c()).await.map(|_| ()), n);
        assert_eq!(sftp.list(b"x", ListOptions::default(), &mut Names::default(), &c()).await, n);
        assert_eq!(sftp.make_dir(b"x", true, &c()).await, n);
        assert_eq!(sftp.remove_file(b"x", &c()).await, n);
        assert_eq!(sftp.remove_dir(b"x", &c()).await, n);
        assert_eq!(sftp.rename(b"x", b"y", RenameMode::Replace, &c()).await, n);
        assert_eq!(sftp.set_attributes(b"x", &Attributes::default(), &c()).await, n);
        assert_eq!(sftp.read_link(b"x", &c()).await.map(|_| ()), n);
        assert_eq!(sftp.make_symlink(b"x", b"y", &c()).await, n);
        assert_eq!(sftp.make_hardlink(b"x", b"y", &c()).await, n);
        assert_eq!(sftp.copy(b"x", b"y", false, RenameMode::Replace, &c()).await, n);
        assert_eq!(sftp.space_info(b"x", &c()).await.map(|_| ()), n);
        assert_eq!(sftp.open_read(b"x", &c()).await.map(|_| ()), n);
        assert_eq!(sftp.open_write(b"x", &WriteOptions::default(), &c()).await.map(|_| ()), n);
        let mut src = Bytes(b"", 0);
        assert_eq!(sftp.upload(b"x", &WriteOptions::default(), &mut src, &mut Quiet, &c()).await, n);
        assert_eq!(sftp.download(b"x", 0, None, &mut Collect::default(), &mut Quiet, &c()).await, n);
        assert_eq!(
            sftp.checksum(b"x", "sha256", &c()).await.map(|_| ()).unwrap_err().name,
            ErrorName::Unsupported
        );
    }
    // Signed in, a tripped token stops every call before it is sent.
    let mut sftp = signed_in(&server).await;
    server.take_log();
    server.fake.take_log();
    let canceled = CancelToken::new();
    canceled.cancel();
    assert_eq!(sftp.stat(b"x", true, &canceled).await.map(|_| ()), Err(Status::canceled()));
    assert_eq!(sftp.keep_alive(&canceled).await, Err(Status::canceled()));
    assert_eq!(server.fake.take_log(), []);
    let mut fresh_one = Sftp::new();
    assert_eq!(fresh_one.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
}

#[tokio::test]
async fn a_changed_key_gets_no_credentials() {
    // SEC-1, S-7: even a caller that skips the identity check.
    let server = Server::start(Script::password()).await;
    let mut sftp = Sftp::new();
    let p = with_option(
        params(server.addr),
        "host_key",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    );
    let seen = sftp.connect(&p, &c()).await.unwrap().unwrap();
    assert_eq!(seen.algorithm, "ssh-ed25519");
    let changed = Status::new(
        ErrorName::ServerIdentityChanged,
        "The server key does not match the saved key; not signing in",
    );
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(changed.clone()));
    // Still connected, still refused.
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(changed));
    assert_eq!(server.take_log(), Vec::<String>::new());
    // The right pin signs in.
    let pin = format!("{} {}", seen.algorithm, BASE64.encode(&seen.public_key));
    let mut sftp = Sftp::new();
    sftp.connect(&with_option(params(server.addr), "host_key", &pin), &c()).await.unwrap();
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
}

#[tokio::test]
async fn refusals_before_sign_in_keep_the_connection() {
    let server = Server::start(Script::password()).await;
    let mut sftp = Sftp::new();
    sftp.connect(&with_option(params(server.addr), "auth_mode", "otp"), &c()).await.unwrap();
    assert_eq!(
        sftp.authenticate(&password(b"secret"), None, &c()).await,
        Err(Status::internal("Unknown sign-in method \"otp\""))
    );
    let mut sftp = Sftp::new();
    sftp.connect(&params(server.addr), &c()).await.unwrap();
    let key = crate::keys::encode_key_secret(b"-----BEGIN OPENSSH PRIVATE KEY-----");
    let wrong = sftp.authenticate(&password(&key), None, &c()).await.unwrap_err();
    assert_eq!(wrong.message, "The account uses a password, but the stored credential is a key");
    let canceled = CancelToken::new();
    canceled.cancel();
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &canceled).await, Err(Status::canceled()));
    assert_eq!(server.take_log(), Vec::<String>::new());
    // The connection is still there to sign in on.
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
}

#[tokio::test]
async fn a_failed_sign_in_closes_the_connection() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    let e = sftp.authenticate(&password(b"wrong"), None, &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AuthFailed);
    assert!(proxy.all_closed().await);
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
}

#[tokio::test]
async fn a_dropped_sign_in_leaves_the_connection_signed_out() {
    // The C ABI drops a call that misses its cancel: nothing half signed in
    // may remain.
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    proxy.stall(true);
    let credentials = password(b"secret");
    let token = c();
    let signing_in = sftp.authenticate(&credentials, None, &token);
    tokio::time::timeout(Duration::from_millis(200), signing_in).await.unwrap_err();
    assert!(proxy.all_closed().await);
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
    assert_eq!(sftp.stat(b"", true, &c()).await.map(|_| ()), Err(not_signed_in()));
}

#[tokio::test]
async fn a_canceled_sign_in_closes_the_connection() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    proxy.stall(true);
    let cancel = c();
    let canceler = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        canceler.cancel();
    });
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &cancel).await, Err(Status::canceled()));
    assert!(proxy.all_closed().await);
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
}

#[tokio::test]
async fn sftp_that_is_not_set_up() {
    for subsystem in [Subsystem::Refuse, Subsystem::Exit] {
        let server = Server::start(Script { subsystem, ..Script::password() }).await;
        let mut sftp = Sftp::new();
        sftp.connect(&params(server.addr), &c()).await.unwrap();
        let e = sftp.authenticate(&password(b"secret"), None, &c()).await;
        assert_eq!(e, Err(sftp_not_enabled()), "{subsystem:?}");
    }
}

#[tokio::test]
async fn the_user_name() {
    let server = Server::start(Script::password()).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(server.addr), &c()).await.unwrap();
    let credentials = Credentials { user: "bob".to_owned(), ..password(b"secret") };
    sftp.authenticate(&credentials, None, &c()).await.unwrap();
    assert_eq!(server.take_log()[..2], ["none bob", "password bob secret"]);
    let settings = Settings::of(&Params { username: String::new(), ..params(server.addr) }).unwrap();
    let local = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    assert_eq!(user_name(&Credentials::default(), &settings), local);
    assert_eq!(user_name(&Credentials::default(), &Settings::of(&params(server.addr)).unwrap()), "alice");
}

#[tokio::test]
async fn connect_replaces_the_connection() {
    let server = Server::start(Script::password()).await;
    let first = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(first.addr), &c()).await.unwrap();
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
    let mut handle = sftp.open_read(b"", &c()).await.err();
    assert_eq!(handle.take().map(|e| e.name), Some(ErrorName::IsADirectory));
    server.fake.file("/home/u/f", b"data");
    let mut reader = sftp.open_read(b"f", &c()).await.unwrap();
    sftp.connect(&params(server.addr), &c()).await.unwrap();
    assert!(first.all_closed().await);
    // Handles of the old connection are gone with it.
    let e = reader.read(0, &mut [0; 4], &c()).await.unwrap_err();
    assert_eq!(e, connection_closed());
    assert_eq!(sftp.capabilities(), Capabilities::default());
    let canceled = c();
    canceled.cancel();
    assert_eq!(sftp.connect(&params(server.addr), &canceled).await, Err(Status::canceled()));
    assert_eq!(sftp.authenticate(&password(b"secret"), None, &c()).await, Err(fresh()));
    let bad = Params { host: String::new(), ..params(server.addr) };
    assert_eq!(sftp.connect(&bad, &c()).await, Err(Status::internal("Invalid server name")));
}

#[tokio::test]
async fn disconnect_ends_handles_and_the_connection() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
    let mut w = sftp.open_write(b"g", &WriteOptions::default(), &c()).await.unwrap();
    sftp.disconnect().await;
    assert!(proxy.all_closed().await);
    assert_eq!(w.write(b"x", &c()).await, Err(connection_closed()));
    sftp.disconnect().await;
    // Connected only: disconnect closes too.
    let proxy = Proxy::start(server.addr).await;
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    sftp.disconnect().await;
    assert!(proxy.all_closed().await);
}

#[tokio::test]
async fn keep_alive_sees_a_lost_connection() {
    let server = Server::start(Script::password()).await;
    let proxy = Proxy::start(server.addr).await;
    let mut sftp = Sftp::new();
    sftp.connect(&params(proxy.addr), &c()).await.unwrap();
    sftp.authenticate(&password(b"secret"), None, &c()).await.unwrap();
    sftp.keep_alive(&c()).await.unwrap();
    proxy.cut();
    let mut lost = None;
    for _ in 0..200 {
        if let Err(e) = sftp.keep_alive(&c()).await {
            lost = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let lost = lost.unwrap();
    assert_eq!(
        (lost.name, lost.message.as_str()),
        (ErrorName::ConnectionLost, "The connection to the server was lost")
    );
    let e = sftp.stat(b"", true, &c()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::ConnectionLost);
    // Signed out only by disconnect.
    sftp.disconnect().await;
    assert_eq!(sftp.keep_alive(&c()).await, Err(not_signed_in()));
}

#[test]
fn backends_and_handles_cross_threads() {
    fn send<T: Send + 'static>() {}
    send::<Sftp>();
    send::<SftpRead>();
    send::<SftpWrite>();
}
