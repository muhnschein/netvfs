// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-smb against the Samba containers of tests/interop/smb (phase 3
//! design §6.3): `tests/interop/smb/run.sh` starts them and sets
//! `NETVFS_INTEROP_SMB_*` (one address per server, the proxy, the password);
//! without those every test passes at once, saying so. These are the tests
//! that cargo-mutants runs in its interop mode, next to the unit tests.
//!
//! The servers and what they show are those of tests/interop/smb/server/conf;
//! the proxy ports those of run.sh (flipproxy.py).
// A test crate: the helpers outside `#[test]` may panic, index and do plain
// arithmetic (clippy.toml relaxes that only inside `#[test]`), and a skip says so.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stderr
)]

use std::time::{Duration, Instant};

use netvfs_smb::auth::Account;
use netvfs_smb::backend::Smb;
use netvfs_smb::conn::{Conn, Element};
use netvfs_smb::crypto::Cipher;
use netvfs_smb::error::Error;
use netvfs_smb::msg::Command;
use netvfs_smb::msg::negotiate::{NegotiateRequest, security_mode};
use netvfs_smb::profile::Profile;
use netvfs_smb::session::{self, GUEST_MAPPED, NO_SMB311, Session};
use netvfs_smb::status::NtStatus;
use netvfs_smb::transport;
use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capability, Credentials, Disposition, Entry, EntryType, ErrorName,
    ListOptions, ListSink, Params, Progress, ReadHandle, RenameMode, Sink, Source, Status, Value,
    WriteHandle, WriteOptions,
};
use zeroize::Zeroizing;

const T: Duration = Duration::from_secs(30);

/// The interop settings, or `None` (the test then passes, saying why).
struct Servers {
    password: String,
}

impl Servers {
    fn get() -> Option<Self> {
        match std::env::var("NETVFS_INTEROP_SMB_PASSWORD") {
            Ok(password) if !password.is_empty() => Some(Self { password }),
            _ => {
                eprintln!("skipped: NETVFS_INTEROP_SMB_* not set (tests/interop/smb/run.sh sets them)");
                None
            }
        }
    }

    fn account(&self) -> Account {
        Account::User {
            user: "backup".into(),
            domain: String::new(),
            password: Zeroizing::new(self.password.clone()),
        }
    }

    fn credentials(&self) -> Credentials {
        Credentials {
            user: "backup".into(),
            secret: Zeroizing::new(self.password.clone().into_bytes()),
            domain: String::new(),
        }
    }

    /// NEGOTIATE and SESSION_SETUP on `server` (port 445 or a proxy port).
    async fn sign_in(
        &self,
        server: &str,
        port: u16,
        profile: Profile,
        account: &Account,
    ) -> Result<Session, Error> {
        let host = host(server);
        let addrs = transport::resolve(&host, port).await?;
        let (stream, _) = transport::connect(&addrs, T).await?;
        session::sign_in(stream, profile, account, &host, T, &CancelToken::new()).await
    }

    /// A backend signed in to `server` with `options` (`share` absent:
    /// server mode).
    async fn backend(&self, server: &str, port: u16, options: &[(&str, &str)]) -> Result<Smb, Status> {
        let mut smb = Smb::new();
        smb.connect(&params(server, port, options), &CancelToken::new()).await?;
        let credentials = if options.contains(&("security_profile", "guest")) {
            Credentials::default()
        } else {
            self.credentials()
        };
        smb.authenticate(&credentials, None, &CancelToken::new()).await?;
        Ok(smb)
    }
}

/// The address of a server (`strict`, `proxy`, ...).
fn host(server: &str) -> String {
    let name = format!("NETVFS_INTEROP_SMB_{}", server.to_uppercase());
    std::env::var(&name).unwrap_or_else(|_unset| panic!("{name} is not set"))
}

/// Connection parameters for `server` (a proxy port or 445).
fn params(server: &str, port: u16, options: &[(&str, &str)]) -> Params {
    Params {
        provider: "smb".into(),
        host: host(server),
        port: i32::from(port),
        username: "backup".into(),
        options: options.iter().map(|(k, v)| ((*k).to_owned(), Value::Str((*v).to_owned()))).collect(),
        ..Params::default()
    }
}

fn share(name: &str) -> [(&'static str, &str); 1] {
    [("share", name)]
}

#[derive(Default)]
struct Names(Vec<Entry>, usize);

impl ListSink for Names {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        self.1 += 1;
        true
    }
}

impl Names {
    fn names(&self) -> Vec<String> {
        self.0.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()).collect()
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

/// Deterministic, incompressible test data (xorshift64).
fn pattern(size: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(size + 8);
    while out.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(size);
    out
}

async fn put(smb: &mut Smb, path: &str, data: &[u8]) -> Result<(), Status> {
    let options = WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() };
    smb.upload(path.as_bytes(), &options, &mut Bytes(data), &mut Quiet, &CancelToken::new()).await
}

async fn get(smb: &mut Smb, path: &str) -> Result<Vec<u8>, Status> {
    let mut sink = Collected::default();
    smb.download(path.as_bytes(), 0, None, &mut sink, &mut Quiet, &CancelToken::new()).await?;
    Ok(sink.0)
}

async fn stat(smb: &mut Smb, path: &str) -> Result<Entry, Status> {
    smb.stat(path.as_bytes(), true, &CancelToken::new()).await
}

// ---- NEGOTIATE and SESSION_SETUP ------------------------------------------

/// M-T1: SMB 3.1.1, the first GCM cipher offered, every response after
/// SESSION_SETUP encrypted; a share, ECHO and LOGOFF on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_server_gets_aes_128_gcm() {
    let Some(servers) = Servers::get() else { return };
    let s = servers.sign_in("strict", 445, Profile::Strict, &servers.account()).await.unwrap();
    assert_eq!(s.negotiated.dialect, 0x0311);
    assert_eq!(s.negotiated.cipher, Some(Cipher::Aes128Gcm));
    assert!(s.negotiated.multi_credit);
    assert!(s.conn.encrypts());
    let cancel = CancelToken::new();
    let tree = session::tree_connect(&s.conn, &host("strict"), "backup", &cancel).await.unwrap();
    session::echo(&s.conn, &cancel).await.unwrap();
    session::tree_disconnect(&s.conn, &tree, &cancel).await.unwrap();
    assert!(s.conn.credits() > 1);
    s.conn.close(true).await;
}

/// M-T14: a server whose only cipher is AES-256-GCM, the second offered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aes_256_gcm_only_server_passes() {
    let Some(servers) = Servers::get() else { return };
    let s = servers.sign_in("aes256", 445, Profile::Strict, &servers.account()).await.unwrap();
    assert_eq!(s.negotiated.cipher, Some(Cipher::Aes256Gcm));
    let tree = session::tree_connect(&s.conn, &host("aes256"), "backup", &CancelToken::new()).await.unwrap();
    assert_eq!(tree.share_type, 1);
    s.conn.close(true).await;
}

/// M-T4: profile signed where the server has encryption off: signed only;
/// M-T3: strict there is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_profile_without_encryption() {
    let Some(servers) = Servers::get() else { return };
    let s = servers.sign_in("encoff", 445, Profile::Signed, &servers.account()).await.unwrap();
    assert!(!s.conn.encrypts());
    let tree = session::tree_connect(&s.conn, &host("encoff"), "backup", &CancelToken::new()).await.unwrap();
    assert!(!tree.encrypt);
    session::echo(&s.conn, &CancelToken::new()).await.unwrap();
    s.conn.close(true).await;
    // M-T3: strict needs encryption, which the server has off (no cipher
    // in its NEGOTIATE response): refused before SESSION_SETUP.
    let e = servers.sign_in("encoff", 445, Profile::Strict, &servers.account()).await.unwrap_err();
    assert!(matches!(&e, Error::Policy(m) if m.contains("no cipher in common")), "{e}");
}

/// M-T7, M-T9, M-T20: servers limited to SMB 2.x or SMB 3.0 refuse the
/// only dialect offered; every profile reports it as policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_dialects_are_refused_by_every_profile() {
    let Some(servers) = Servers::get() else { return };
    for server in ["smb2only", "smb300"] {
        for profile in Profile::ALL {
            let account = if profile == Profile::Guest { Account::Anonymous } else { servers.account() };
            let e = servers.sign_in(server, 445, profile, &account).await.unwrap_err();
            assert_eq!(e, Error::Policy(NO_SMB311.into()), "{server}, {profile:?}");
        }
    }
}

/// M-T7: a NEGOTIATE that offers SMB 2.1 only (test code: the client has
/// no SMB 2 dialect) is not accepted by the strict server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_pinned_to_smb_2_1_is_refused() {
    if Servers::get().is_none() {
        return;
    }
    let addrs = transport::resolve(&host("strict"), 445).await.unwrap();
    let (stream, _) = transport::connect(&addrs, T).await.unwrap();
    let conn = Conn::start(stream, T);
    let request = NegotiateRequest {
        security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
        capabilities: 0,
        client_guid: [7; 16],
        dialects: vec![0x0210],
        contexts: Vec::new(),
    };
    let answer =
        conn.call_raw(Element::new(Command::Negotiate, request.encode().unwrap()), &CancelToken::new()).await;
    match answer {
        Ok((resp, _)) => assert_eq!(resp.status(), NtStatus::NOT_SUPPORTED),
        Err(e) => assert!(matches!(e, Error::Lost(_)), "{e}"),
    }
    conn.abort();
}

/// M-1: a NEGOTIATE reply rewritten to SMB 2.1 (proxy 4457) ends the sign-in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialect_never_offered_is_refused() {
    let Some(servers) = Servers::get() else { return };
    let e = servers.sign_in("proxy", 4457, Profile::Strict, &servers.account()).await.unwrap_err();
    assert!(matches!(&e, Error::Policy(m) if m.contains("0x0210")), "{e}");
}

/// M-T14: AES-CCM only. Strict finds no cipher; signed is refused by Samba
/// itself (required) or by the client, since Samba marks the session for
/// encryption without a cipher (desired).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ccm_only_servers_are_refused() {
    let Some(servers) = Servers::get() else { return };
    for server in ["ccmonly", "ccmdesired"] {
        let e = servers.sign_in(server, 445, Profile::Strict, &servers.account()).await.unwrap_err();
        assert!(matches!(&e, Error::Policy(m) if m.contains("no cipher in common")), "{server}: {e}");
    }
    let e = servers.sign_in("ccmonly", 445, Profile::Signed, &servers.account()).await.unwrap_err();
    assert_eq!(e, Error::Status(NtStatus::ACCESS_DENIED));
    let e = servers.sign_in("ccmdesired", 445, Profile::Signed, &servers.account()).await.unwrap_err();
    assert!(matches!(&e, Error::Policy(m) if m.contains("no common cipher")), "{e}");
}

/// M-T14: signing only with AES-GMAC and HMAC-SHA256; the client signs
/// with AES-CMAC only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gmac_only_signing_server_is_refused() {
    let Some(servers) = Servers::get() else { return };
    let e = servers.sign_in("gmac", 445, Profile::Signed, &servers.account()).await.unwrap_err();
    assert!(matches!(e, Error::Policy(_) | Error::Status(_)), "{e}");
}

/// M-T5: a wrong password and an unknown user; M-T6: an unknown share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_and_share_names() {
    let Some(servers) = Servers::get() else { return };
    for (user, password) in
        [("backup", format!("{}x", servers.password)), ("nosuchuser", servers.password.clone())]
    {
        let account =
            Account::User { user: user.into(), domain: String::new(), password: Zeroizing::new(password) };
        let e = servers.sign_in("strict", 445, Profile::Strict, &account).await.unwrap_err();
        assert_eq!(e, Error::Status(NtStatus::LOGON_FAILURE), "{user}");
    }
    let s = servers.sign_in("strict", 445, Profile::Strict, &servers.account()).await.unwrap();
    let e = session::tree_connect(&s.conn, &host("strict"), "nosuchshare", &CancelToken::new())
        .await
        .unwrap_err();
    assert_eq!(e, Error::Status(NtStatus::BAD_NETWORK_NAME));
    s.conn.close(true).await;

    let mut smb = Smb::new();
    let cancel = CancelToken::new();
    smb.connect(&params("strict", 445, &share("nosuchshare")), &cancel).await.unwrap();
    let e = smb.authenticate(&servers.credentials(), None, &cancel).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NotFound);
    assert!(e.message.contains("share not found") && e.message.contains("0xc00000cc"), "{}", e.message);
}

/// XM-1: an unknown user mapped to guest is refused by strict and signed;
/// profile guest signs in anonymously and uses the public share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_mapping_and_the_guest_profile() {
    let Some(servers) = Servers::get() else { return };
    let stranger = Account::User {
        user: "nosuchuser".into(),
        domain: String::new(),
        password: Zeroizing::new("whatever".into()),
    };
    for profile in [Profile::Strict, Profile::Signed] {
        let e = servers.sign_in("guest", 445, profile, &stranger).await.unwrap_err();
        assert_eq!(e, Error::Policy(GUEST_MAPPED.into()), "{profile:?}");
    }
    let mut smb =
        servers.backend("guest", 445, &[("share", "public"), ("security_profile", "guest")]).await.unwrap();
    put(&mut smb, "guest-rs.txt", b"guest").await.unwrap();
    assert_eq!(get(&mut smb, "guest-rs.txt").await.unwrap(), b"guest");
    smb.remove_file(b"guest-rs.txt", &CancelToken::new()).await.unwrap();
    smb.disconnect().await;
    // A server that maps no guest.
    let e = servers.sign_in("strict", 445, Profile::Guest, &Account::Anonymous).await.unwrap_err();
    assert!(matches!(e, Error::Policy(_) | Error::Status(_)), "{e}");
}

// ---- Integrity: the flip proxy (M-T12) -------------------------------------

/// MS-SMB2 3.2.5.3.1: the final SESSION_SETUP reply with one byte altered
/// (proxy 4459) does not verify with the new session's signing key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_session_setup_reply_is_refused() {
    let Some(servers) = Servers::get() else { return };
    let e = servers.sign_in("proxy", 4459, Profile::Strict, &servers.account()).await.unwrap_err();
    assert_eq!(
        e,
        Error::Policy("the final SESSION_SETUP response: message signature does not verify".into())
    );
}

/// M-T12: the first reply after sign-in altered, signed (4451) and sealed
/// (4452): the connection is lost, and stays lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_reply_ends_the_connection() {
    let Some(servers) = Servers::get() else { return };
    // Control: the same path without tampering.
    let mut control =
        servers.backend("proxy", 4450, &[("share", "backup"), ("security_profile", "signed")]).await.unwrap();
    stat(&mut control, "").await.unwrap();
    control.disconnect().await;
    for (port, profile) in [(4451, "signed"), (4452, "strict")] {
        let mut smb = servers
            .backend("proxy", port, &[("share", "backup"), ("security_profile", profile)])
            .await
            .unwrap();
        let e = stat(&mut smb, "").await.unwrap_err();
        assert_eq!(e.name, ErrorName::ConnectionLost, "{port}: {}", e.message);
        assert_eq!(stat(&mut smb, "").await.unwrap_err().name, ErrorName::ConnectionLost);
    }
}

// ---- Stalls, drops, timeouts ------------------------------------------------

/// M-12: a request stalled on the network (proxy 4453) ends within 2 s of
/// the cancel; C-14: with a 2 s request timeout it ends as Timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_requests_cancel_and_time_out() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("proxy", 4453, &share("backup")).await.unwrap();
    let cancel = CancelToken::new();
    let trip = cancel.clone();
    let canceled_at = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        trip.cancel();
        Instant::now()
    });
    let e = smb.stat(b"", true, &cancel).await.unwrap_err();
    let returned = Instant::now();
    assert_eq!(e.name, ErrorName::Canceled);
    assert!(returned.duration_since(canceled_at.await.unwrap()) < Duration::from_secs(2));
    let closing = Instant::now();
    smb.disconnect().await;
    assert!(closing.elapsed() < Duration::from_secs(2));

    let mut params = params("proxy", 4453, &share("backup"));
    params.request_timeout_ms = 2000;
    let mut smb = Smb::new();
    smb.connect(&params, &CancelToken::new()).await.unwrap();
    smb.authenticate(&servers.credentials(), None, &CancelToken::new()).await.unwrap();
    let started = Instant::now();
    assert_eq!(stat(&mut smb, "").await.unwrap_err().name, ErrorName::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

/// M-12: a sign-in stalled after NEGOTIATE (proxy 4454) ends on cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_sign_in_cancels() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = Smb::new();
    smb.connect(&params("proxy", 4454, &share("backup")), &CancelToken::new()).await.unwrap();
    let cancel = CancelToken::new();
    let trip = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        trip.cancel();
    });
    let started = Instant::now();
    let e = smb.authenticate(&servers.credentials(), None, &cancel).await.unwrap_err();
    assert_eq!(e.name, ErrorName::Canceled);
    assert!(started.elapsed() < Duration::from_millis(2500), "{:?}", started.elapsed());
}

/// XC-20, XC-21: dropped after sign-in (4455): ConnectionLost; during
/// sign-in (4456): SecurityPolicy, the server closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_connections() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("proxy", 4455, &share("backup")).await.unwrap();
    assert_eq!(smb.keep_alive(&CancelToken::new()).await.unwrap_err().name, ErrorName::ConnectionLost);
    assert_eq!(smb.keep_alive(&CancelToken::new()).await.unwrap_err().name, ErrorName::ConnectionLost);
    let e = servers.backend("proxy", 4456, &share("backup")).await.unwrap_err();
    assert_eq!(e.name, ErrorName::SecurityPolicy);
}

// ---- The backend on a share --------------------------------------------------

/// XC-5, XC-8..XC-14, XC-19: the namespace and transfers on the strict
/// server, with multi-credit READ and WRITE (more than 1 MiB per file).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_round_trip() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("strict", 445, &share("backup")).await.unwrap();
    let caps = smb.capabilities();
    for cap in [
        Capability::AtomicReplace,
        Capability::NativeNoReplace,
        Capability::ReadHandles,
        Capability::WriteResume,
    ] {
        assert!(caps.flags.contains(&cap), "{cap:?}");
    }
    assert!(!caps.flags.contains(&Capability::ShareEnumeration));
    let cancel = CancelToken::new();
    let dir = "rs round trip/f\u{fc}r J\u{f6}rg";
    smb.make_dir(b"rs round trip", false, &cancel).await.unwrap();
    smb.make_dir(dir.as_bytes(), false, &cancel).await.unwrap();
    assert_eq!(smb.make_dir(dir.as_bytes(), true, &cancel).await.unwrap_err().name, ErrorName::AlreadyExists);

    let content = pattern(3 * 1024 * 1024 + 17, 42);
    let big = format!("{dir}/big.bin");
    put(&mut smb, &big, &content).await.unwrap();
    assert_eq!(stat(&mut smb, &big).await.unwrap().size, Some(content.len() as u64));
    assert!(get(&mut smb, &big).await.unwrap() == content);
    let mut ranged = Collected::default();
    smb.download(big.as_bytes(), 1000, Some(1024 * 1024 + 5), &mut ranged, &mut Quiet, &cancel)
        .await
        .unwrap();
    assert!(ranged.0 == content[1000..1000 + 1024 * 1024 + 5]);

    // A read handle with read-ahead, then reads elsewhere.
    let mut handle = smb.open_read(big.as_bytes(), &cancel).await.unwrap();
    assert_eq!(handle.size(), Some(content.len() as u64));
    handle.read_ahead(0, 3 * 1024 * 1024);
    let mut buf = vec![0; 10];
    assert_eq!(handle.read(2 * 1024 * 1024 + 7, &mut buf, &cancel).await.unwrap(), 10);
    assert_eq!(buf, content[2 * 1024 * 1024 + 7..][..10]);
    let mut tail = vec![0; 100];
    assert_eq!(handle.read(content.len() as u64 - 4, &mut tail, &cancel).await.unwrap(), 4);
    assert_eq!(handle.read(content.len() as u64, &mut tail, &cancel).await.unwrap(), 0);
    handle.close(&cancel).await.unwrap();

    // Resume a write at the remote size, with a modification time.
    let small = format!("{dir}/small.bin");
    put(&mut smb, &small, b"0123456789").await.unwrap();
    let when = 1_614_834_367_000;
    let resume = WriteOptions {
        disposition: Disposition::Resume,
        resume_offset: 10,
        mtime_ms: Some(when),
        ..WriteOptions::default()
    };
    let mut writer = smb.open_write(small.as_bytes(), &resume, &cancel).await.unwrap();
    assert_eq!(writer.position(), 10);
    writer.write(&content[..2 * 1024 * 1024], &cancel).await.unwrap();
    writer.commit(&cancel).await.unwrap();
    let entry = stat(&mut smb, &small).await.unwrap();
    assert_eq!((entry.size, entry.mtime_ms), (Some(10 + 2 * 1024 * 1024), Some(when)));
    let wrong = WriteOptions { resume_offset: 9, ..resume };
    assert_eq!(
        smb.open_write(small.as_bytes(), &wrong, &cancel).await.err().unwrap().name,
        ErrorName::ProtocolError
    );

    // XC-10: NoReplace is the server's; Replace replaces a file.
    let e = smb.rename(small.as_bytes(), big.as_bytes(), RenameMode::NoReplace, &cancel).await.unwrap_err();
    assert_eq!(e.name, ErrorName::AlreadyExists);
    smb.rename(small.as_bytes(), big.as_bytes(), RenameMode::Replace, &cancel).await.unwrap();
    assert_eq!(stat(&mut smb, &small).await.unwrap_err().name, ErrorName::NotFound);
    assert_eq!(stat(&mut smb, &big).await.unwrap().size, Some(10 + 2 * 1024 * 1024));

    // XC-11: times only.
    let times = Attributes { atime_ms: Some(when + 86_400_000), ..Attributes::default() };
    smb.set_attributes(big.as_bytes(), &times, &cancel).await.unwrap();
    let entry = stat(&mut smb, &big).await.unwrap();
    assert_eq!((entry.mtime_ms, entry.atime_ms), (Some(when), Some(when + 86_400_000)));
    let mode = Attributes { mode: Some(0o644), ..Attributes::default() };
    assert_eq!(
        smb.set_attributes(big.as_bytes(), &mode, &cancel).await.unwrap_err().name,
        ErrorName::Unsupported
    );

    // XC-6: batches, no dot entries.
    for i in 0..9 {
        put(&mut smb, &format!("{dir}/f{i}"), &vec![b'x'; i]).await.unwrap();
    }
    let mut names = Names::default();
    let options = ListOptions { batch_size: 4, ..ListOptions::default() };
    smb.list(dir.as_bytes(), options, &mut names, &cancel).await.unwrap();
    let mut listed = names.names();
    listed.sort();
    assert_eq!(listed, ["big.bin", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"]);
    assert_eq!(names.1, 3);
    assert!(names.0.iter().all(|e| e.kind == EntryType::File && e.mode.is_none()));

    let space = smb.space_info(dir.as_bytes(), &cancel).await.unwrap();
    assert!(space.total.unwrap() > 0 && space.free.unwrap() <= space.total.unwrap());
    smb.keep_alive(&cancel).await.unwrap();

    // XC-9
    assert_eq!(smb.remove_dir(dir.as_bytes(), &cancel).await.unwrap_err().name, ErrorName::DirectoryNotEmpty);
    assert_eq!(smb.remove_file(dir.as_bytes(), &cancel).await.unwrap_err().name, ErrorName::IsADirectory);
    for name in listed {
        smb.remove_file(format!("{dir}/{name}").as_bytes(), &cancel).await.unwrap();
    }
    smb.remove_dir(dir.as_bytes(), &cancel).await.unwrap();
    smb.remove_dir(b"rs round trip", &cancel).await.unwrap();
    assert_eq!(smb.remove_dir(b"rs round trip", &cancel).await.unwrap_err().name, ErrorName::NotFound);
    smb.disconnect().await;
}

/// The account may read but not write: PermissionDenied, not a sign-in error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_share() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("strict", 445, &share("readonly")).await.unwrap();
    assert_eq!(put(&mut smb, "new.txt", b"x").await.unwrap_err().name, ErrorName::PermissionDenied);
    assert_eq!(get(&mut smb, "existing.txt").await.unwrap(), b"read-only share\n");
}

/// M-T16: the 16 MiB share: the server's DISK_FULL is NoSpace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_share() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("strict", 445, &share("small")).await.unwrap();
    let data = pattern(17 * 1024 * 1024, 7);
    let options = WriteOptions { disposition: Disposition::Truncate, ..WriteOptions::default() };
    let mut source = Bytes(&data);
    let e =
        smb.upload(b"rs-full.bin", &options, &mut source, &mut Quiet, &CancelToken::new()).await.unwrap_err();
    assert_eq!(e.name, ErrorName::NoSpace, "{}", e.message);
    smb.remove_file(b"rs-full.bin", &CancelToken::new()).await.unwrap();
}

/// XM-9: a DFS link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dfs_link_is_unsupported() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("strict", 445, &share("dfs")).await.unwrap();
    let e = stat(&mut smb, "away").await.unwrap_err();
    assert_eq!((e.name, e.detail.as_str()), (ErrorName::Unsupported, "DFS referral"));
}

// ---- Server mode -------------------------------------------------------------

/// XM-2, XM-3, XM-7: the root lists the shares (srvsvc over IPC$): saved
/// names first, disk shares only, admin shares on request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_mode_lists_shares() {
    let Some(servers) = Servers::get() else { return };
    let mut smb = servers.backend("strict", 445, &[("shares", "backup, Saved")]).await.unwrap();
    assert!(smb.capabilities().flags.contains(&Capability::ShareEnumeration));
    let mut names = Names::default();
    smb.list(b"/", ListOptions::default(), &mut names, &CancelToken::new()).await.unwrap();
    assert_eq!(names.names(), ["backup", "Saved", "readonly", "small", "media", "dfs"]);
    assert!(names.0.iter().all(|e| e.kind == EntryType::Directory));
    assert_eq!(stat(&mut smb, "/media").await.unwrap().kind, EntryType::Directory);
    assert_eq!(stat(&mut smb, "/Saved").await.unwrap_err().name, ErrorName::NotFound);
    // Inside a share, as in share mode.
    put(&mut smb, "/media/rs-server-mode.txt", b"server mode").await.unwrap();
    assert_eq!(get(&mut smb, "/MEDIA/rs-server-mode.txt").await.unwrap(), b"server mode");
    smb.remove_file(b"/media/rs-server-mode.txt", &CancelToken::new()).await.unwrap();

    let mut admin = servers.backend("strict", 445, &[("show_admin_shares", "true")]).await.unwrap();
    let mut names = Names::default();
    admin.list(b"/", ListOptions::default(), &mut names, &CancelToken::new()).await.unwrap();
    let names = names.names();
    assert!(names.iter().any(|n| n == "hidden$") && !names.iter().any(|n| n == "IPC$"), "{names:?}");
}
