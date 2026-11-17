// SPDX-License-Identifier: LGPL-2.1-or-later
//! netvfs-sftp against real servers: the interop containers of tests/interop/sftp (OpenSSH 10.3p1, 9.6p1 and 8.9p1),
//! which `run.sh` starts and describes in the file `NETVFS_SFTP_INTEROP_CONFIG` names. Without it every test passes at
//! once and says it was skipped.
//!
//! Tests run in parallel against shared servers: each works in folders of its own, and reads a server log only for
//! lines its own connection adds.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stderr
)]

use netvfs_sftp::backend::Sftp;
use netvfs_sftp::keys;
use netvfs_vfs::{
    Attributes, Backend, CancelToken, Capability, Credentials, Disposition, Entry, EntryType, ErrorName,
    ListOptions, ListSink, Params, Progress, PromptRequest, Prompter, ReadHandle, RenameMode, Sink, Source,
    Status, Value, WriteHandle, WriteOptions, Zeroizing,
};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// The servers of one run.sh.
struct Servers {
    password: String,
    otp: String,
    by_name: serde_json::Value,
}

/// The servers, or `None` (and a note) when run.sh did not start them.
fn servers() -> Option<Servers> {
    let Some(path) = std::env::var_os("NETVFS_SFTP_INTEROP_CONFIG") else {
        eprintln!("skipped: NETVFS_SFTP_INTEROP_CONFIG is not set (tests/interop/sftp/run.sh sets it)");
        return None;
    };
    let text = std::fs::read(&path).expect("the interop configuration");
    let config: serde_json::Value = serde_json::from_slice(&text).expect("the configuration is JSON");
    let field = |key: &str| config[key].as_str().expect("a configuration string").to_owned();
    Some(Servers { password: field("password"), otp: field("otp"), by_name: config["servers"].clone() })
}

impl Servers {
    fn port(&self, server: &str, instance: &str) -> i32 {
        let port = self.by_name[server]["ports"][instance].as_i64().expect("a port of the configuration");
        i32::try_from(port).expect("a port")
    }

    /// `sh -c script` in the server's container, as root, with `input` on
    /// its standard input; its output. A failing script fails the test.
    fn exec(&self, server: &str, script: &str, input: &[u8]) -> Vec<u8> {
        let container = self.by_name[server]["container"].as_str().expect("a container");
        let mut child = Command::new("docker")
            .args(["exec", "-i", container, "sh", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker");
        child.stdin.take().expect("stdin").write_all(input).expect("input");
        let out = child.wait_with_output().expect("docker exec");
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    fn text(&self, server: &str, script: &str) -> String {
        String::from_utf8(self.exec(server, script, b"")).expect("UTF-8").trim_end().to_owned()
    }

    /// How often `line` is in the log of an OpenSSH instance.
    fn log_count(&self, server: &str, instance: &str, line: &str) -> usize {
        self.text(server, &format!("cat /var/log/sshd-{instance}.log")).matches(line).count()
    }

    fn params(&self, server: &str, instance: &str, user: &str, auth_mode: Option<&str>) -> Params {
        let mut p = Params {
            provider: "sftp".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: self.port(server, instance),
            username: user.to_owned(),
            connect_timeout_ms: 20_000,
            request_timeout_ms: 30_000,
            ..Params::default()
        };
        if let Some(mode) = auth_mode {
            p.options.insert("auth_mode".to_owned(), Value::Str(mode.to_owned()));
        }
        p
    }

    /// The pin of the server's host key of `kind` (ed25519, ecdsa, rsa).
    fn host_key(&self, server: &str, kind: &str) -> String {
        let line = self.text(server, &format!("cat /etc/ssh/ssh_host_{kind}_key.pub"));
        line.split(' ').take(2).collect::<Vec<_>>().join(" ")
    }

    /// Adds `key` to the keys of `user` on an OpenSSH server.
    fn authorize(&self, server: &str, user: &str, key: &keys::KeyMaterial) {
        let file = format!("/etc/ssh/authorized_keys/{user}");
        let script = format!("cat >> {file} && chmod 644 {file}");
        self.exec(server, &script, format!("{}\n", key.public_line).as_bytes());
    }

    fn credentials(&self, user: &str) -> Credentials {
        Credentials {
            user: user.to_owned(),
            secret: Zeroizing::new(self.password.clone().into_bytes()),
            ..Credentials::default()
        }
    }
}

fn with_pin(mut p: Params, pin: &str) -> Params {
    p.options.insert("host_key".to_owned(), Value::Str(pin.to_owned()));
    p
}

fn key_credentials(user: &str, key: &keys::KeyMaterial) -> Credentials {
    Credentials {
        user: user.to_owned(),
        secret: keys::encode_key_secret(&key.private_key),
        ..Credentials::default()
    }
}

fn c() -> CancelToken {
    CancelToken::new()
}

/// A name no other test (or earlier run) uses.
fn unique(prefix: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    format!("{prefix}-{}-{nanos}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Connects, pins what the server presents, and signs in.
async fn sign_in(params: &Params, credentials: &Credentials) -> Result<Sftp, Status> {
    let mut sftp = Sftp::new();
    let identity = sftp.connect(params, &c()).await?.expect("an identity");
    let pin = format!("{} {}", identity.algorithm, data_encoding::BASE64.encode(&identity.public_key));
    sftp.connect(&with_pin(params.clone(), &pin), &c()).await?;
    sftp.authenticate(credentials, None, &c()).await?;
    Ok(sftp)
}

async fn password_session(s: &Servers, server: &str, instance: &str) -> Sftp {
    sign_in(&s.params(server, instance, "alice", None), &s.credentials("alice"))
        .await
        .unwrap_or_else(|e| panic!("{server} {instance}: {e:?}"))
}

struct Bytes<'a>(&'a [u8]);
impl Source for Bytes<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
    fn size(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

#[derive(Default)]
struct Collect(Vec<u8>);
impl Sink for Collect {
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

#[derive(Default)]
struct Entries(Vec<Entry>);
impl ListSink for Entries {
    fn entries(&mut self, batch: &[Entry]) -> bool {
        self.0.extend_from_slice(batch);
        true
    }
}

/// Answers by prompt text and records the questions.
struct Answers {
    password: String,
    code: String,
    asked: Vec<String>,
}
impl Prompter for Answers {
    fn answer(&mut self, request: &PromptRequest) -> Option<Vec<Zeroizing<Vec<u8>>>> {
        let mut answers = Vec::new();
        for prompt in &request.prompts {
            self.asked.push(prompt.text.clone());
            let answer = if prompt.text.contains("Password") { &self.password } else { &self.code };
            answers.push(Zeroizing::new(answer.clone().into_bytes()));
        }
        Some(answers)
    }
}

async fn put(sftp: &mut Sftp, path: &str, data: &[u8], options: &WriteOptions) -> Result<(), Status> {
    sftp.upload(path.as_bytes(), options, &mut Bytes(data), &mut Quiet, &c()).await
}

async fn get(sftp: &mut Sftp, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>, Status> {
    let mut sink = Collect::default();
    sftp.download(path.as_bytes(), offset, length, &mut sink, &mut Quiet, &c()).await?;
    Ok(sink.0)
}

/// What each server negotiates with the hardened lists, read from the lines this test's own sign-in adds to the
/// server's log.
#[tokio::test]
async fn negotiates_the_hardened_lists() {
    let Some(s) = servers() else { return };
    for (server, instance, kex) in [
        ("o103", "default", "mlkem768x25519-sha256"),
        ("o103", "curve", "curve25519-sha256"),
        ("o96", "default", "curve25519-sha256"),
        ("o89", "default", "curve25519-sha256"),
    ] {
        let lines = [
            format!("kex: algorithm: {kex}"),
            "kex: host key algorithm: ssh-ed25519".to_owned(),
            "kex: client->server cipher: chacha20-poly1305@openssh.com".to_owned(),
            "kex: server->client cipher: chacha20-poly1305@openssh.com".to_owned(),
        ];
        let before: Vec<usize> = lines.iter().map(|l| s.log_count(server, instance, l)).collect();
        let mut sftp = Sftp::new();
        let identity = sftp.connect(&s.params(server, instance, "alice", None), &c()).await.unwrap().unwrap();
        assert_eq!(identity.algorithm, "ssh-ed25519", "{server} {instance}");
        sftp.disconnect().await;
        for (line, count) in lines.iter().zip(before) {
            assert!(s.log_count(server, instance, line) > count, "{server} {instance}: {line}");
        }
    }
}

/// The lists are never widened; a server that offers only what they leave out is refused, and the message says what
/// it offers.
#[tokio::test]
async fn refuses_what_the_lists_leave_out() {
    let Some(s) = servers() else { return };
    for (server, instance, list, offered) in [
        ("o96", "legacy", "key exchange", "diffie-hellman-group14-sha1"),
        ("o103", "dh", "key exchange", "diffie-hellman-group16-sha512, diffie-hellman-group14-sha256"),
        ("o103", "cbc", "cipher", "aes256-cbc, aes128-cbc"),
        ("o103", "sha1rsa", "host key", "ssh-rsa"),
    ] {
        let expected = Status::new(
            ErrorName::SecurityPolicy,
            format!("The server offers no {list} algorithm this app accepts (it offers {offered})"),
        );
        let mut sftp = Sftp::new();
        let p = s.params(server, instance, "alice", None);
        assert_eq!(sftp.connect(&p, &c()).await, Err(expected.clone()), "{instance}");
        // Narrowed to a pinned type, the refusal is the same.
        let pinned = with_pin(p, &s.host_key(server, "rsa"));
        assert_eq!(sftp.connect(&pinned, &c()).await, Err(expected), "{instance} pinned");
    }
}

/// Each host key type pins (the list is narrowed to the pinned type, rsa-sha2-512 for RSA); a pinned type the server
/// no longer offers reports the key it has now, and nothing is sent.
#[tokio::test]
async fn pins_each_host_key_type() {
    let Some(s) = servers() else { return };
    for (kind, algorithm, negotiated) in [
        ("ed25519", "ssh-ed25519", "ssh-ed25519"),
        ("ecdsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
        ("rsa", "ssh-rsa", "rsa-sha2-512"),
    ] {
        let pin = s.host_key("o103", kind);
        let line = format!("kex: host key algorithm: {negotiated}");
        let before = s.log_count("o103", "default", &line);
        let mut sftp = Sftp::new();
        let identity = sftp
            .connect(&with_pin(s.params("o103", "default", "alice", None), &pin), &c())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.algorithm, algorithm);
        assert_eq!(
            format!("{} {}", identity.algorithm, data_encoding::BASE64.encode(&identity.public_key)),
            pin
        );
        let fingerprint = s.text("o103", &format!("ssh-keygen -lf /etc/ssh/ssh_host_{kind}_key.pub"));
        assert_eq!(fingerprint.split(' ').nth(1), Some(identity.fingerprint.as_str()));
        sftp.authenticate(&s.credentials("alice"), None, &c()).await.unwrap();
        sftp.stat(b"", true, &c()).await.unwrap();
        assert!(s.log_count("o103", "default", &line) > before, "{line}");
    }

    // The hardened instance has only its Ed25519 key.
    let probe = unique("pinprobe");
    let mut sftp = Sftp::new();
    let p = with_pin(s.params("o103", "hardened", &probe, None), &s.host_key("o103", "ecdsa"));
    let identity = sftp.connect(&p, &c()).await.unwrap().unwrap();
    let current = s.host_key("o103", "ed25519");
    assert_eq!(
        format!("{} {}", identity.algorithm, data_encoding::BASE64.encode(&identity.public_key)),
        current
    );
    let refused = sftp.authenticate(&s.credentials(&probe), None, &c()).await.unwrap_err();
    assert_eq!(refused.name, ErrorName::ServerIdentityChanged);
    // A key of the same type that is not the server's.
    let other = with_pin(s.params("o103", "default", &probe, None), &s.host_key("o96", "ed25519"));
    sftp.connect(&other, &c()).await.unwrap();
    let refused = sftp.authenticate(&s.credentials(&probe), None, &c()).await.unwrap_err();
    assert_eq!(refused.name, ErrorName::ServerIdentityChanged);
    for instance in ["hardened", "default"] {
        assert_eq!(s.log_count("o103", instance, &probe), 0, "{instance}");
    }
}

/// Passwords and Ed25519/ECDSA keys; a password is never tried as a key nor a key as a password.
#[tokio::test]
async fn signs_in_with_passwords_and_keys() {
    let Some(s) = servers() else { return };
    let mut sftp = password_session(&s, "o103", "default").await;
    assert!(sftp.stat(b"", true, &c()).await.unwrap().kind == EntryType::Directory);
    sftp.disconnect().await;

    let wrong =
        Credentials { secret: Zeroizing::new(b"not the password".to_vec()), ..s.credentials("alice") };
    let failed = sign_in(&s.params("o103", "default", "alice", None), &wrong).await.err().unwrap();
    assert_eq!(failed.name, ErrorName::AuthFailed);
    assert!(failed.message.contains("password"), "{failed:?}");

    // Keys: generated Ed25519, and ECDSA keys of the server's ssh-keygen.
    let user = "alice";
    let mut keys = vec![keys::generate().unwrap()];
    for bits in [256, 384, 521] {
        let file = s.exec(
            "o103",
            &format!("rm -f /tmp/k{bits} /tmp/k{bits}.pub && ssh-keygen -q -t ecdsa -b {bits} -N '' -f /tmp/k{bits} && cat /tmp/k{bits}"),
            b"",
        );
        let key = keys::import(&file, b"").unwrap();
        assert_eq!(key.algorithm, format!("ecdsa-sha2-nistp{bits}"));
        keys.push(key);
    }
    for key in &keys {
        s.authorize("o103", user, key);
    }
    let key_params = s.params("o103", "default", user, Some("publickey"));
    for key in &keys {
        let mut sftp = sign_in(&key_params, &key_credentials(user, key)).await.unwrap_or_else(|e| {
            panic!("{}: {e:?}", key.algorithm);
        });
        sftp.stat(b"", true, &c()).await.unwrap();
    }
    // A password in publickey mode, a key in password mode: refused here.
    let probe = unique("keyprobe");
    let as_key =
        sign_in(&s.params("o103", "default", &probe, Some("publickey")), &s.credentials(&probe)).await;
    assert_eq!(as_key.err().map(|e| e.name), Some(ErrorName::AuthFailed));
    let as_password =
        sign_in(&s.params("o103", "default", &probe, None), &key_credentials(&probe, &keys[0])).await;
    assert_eq!(as_password.err().map(|e| e.name), Some(ErrorName::AuthFailed));
    assert_eq!(s.log_count("o103", "default", &probe), 0);

    // A key-only server says so; the password is not offered.
    let probe = unique("pwprobe");
    let refused =
        sign_in(&s.params("o103", "hardened", &probe, None), &s.credentials(&probe)).await.err().unwrap();
    assert_eq!(refused.name, ErrorName::AuthFailed);
    assert!(refused.message.contains("only accepts SSH keys"), "{refused:?}");
    assert_eq!(s.log_count("o103", "hardened", &format!("method password for invalid user {probe}")), 0);

    // A second step without a prompter is refused, not half done.
    let twofactor = keys::generate().unwrap();
    s.authorize("o103", "twofactor", &twofactor);
    let credentials = key_credentials("twofactor", &twofactor);
    let partial = sign_in(&s.params("o103", "default", "twofactor", Some("publickey")), &credentials)
        .await
        .err()
        .unwrap();
    assert_eq!(partial.name, ErrorName::AuthFailed);
    assert!(partial.message.contains("second sign-in step"), "{partial:?}");
}

/// Keyboard-interactive with the stored password, and with a prompter through PAM's one-time code stub.
#[tokio::test]
async fn keyboard_interactive() {
    let Some(s) = servers() else { return };
    let mut sftp = password_session(&s, "o96", "kbdint").await;
    sftp.stat(b"", true, &c()).await.unwrap();
    let wrong = Credentials { secret: Zeroizing::new(b"wrong".to_vec()), ..s.credentials("alice") };
    let failed = sign_in(&s.params("o96", "kbdint", "alice", None), &wrong).await.err().unwrap();
    assert_eq!(failed.name, ErrorName::AuthFailed);

    // Two rounds (password, code): refused without a prompter...
    let otp = s.params("o96", "otp", "otp", None);
    let refused = sign_in(&otp, &s.credentials("otp")).await.err().unwrap();
    assert_eq!(refused.name, ErrorName::AuthFailed);
    assert!(refused.message.contains("interactive sign-in"), "{refused:?}");
    // ... and with one, only the code is asked: the password answers its round.
    let mut sftp = Sftp::new();
    let identity = sftp.connect(&otp, &c()).await.unwrap().unwrap();
    let pin = format!("{} {}", identity.algorithm, data_encoding::BASE64.encode(&identity.public_key));
    sftp.connect(&with_pin(otp.clone(), &pin), &c()).await.unwrap();
    let mut answers = Answers { password: s.password.clone(), code: s.otp.clone(), asked: Vec::new() };
    sftp.authenticate(&s.credentials("otp"), Some(&mut answers), &c()).await.unwrap();
    assert_eq!(answers.asked, ["Verification code: "]);
    sftp.stat(b"", true, &c()).await.unwrap();

    // A wrong code fails.
    sftp.connect(&with_pin(otp, &pin), &c()).await.unwrap();
    let mut wrong = Answers { password: s.password.clone(), code: "000000".to_owned(), asked: Vec::new() };
    let failed = sftp.authenticate(&s.credentials("otp"), Some(&mut wrong), &c()).await.unwrap_err();
    assert_eq!(failed.name, ErrorName::AuthFailed);
}

/// What each server offers, and so what the backend reports.
#[tokio::test]
async fn capabilities_of_each_server() {
    let Some(s) = servers() else { return };
    let always = [
        Capability::ReadHandles,
        Capability::EfficientRanges,
        Capability::WriteResume,
        Capability::PosixModes,
        Capability::SetModified,
        Capability::SetModifiedOnUpload,
        Capability::Symlinks,
        Capability::NativeNoReplace,
    ];
    let never = [Capability::ServerCopyRecursive, Capability::Checksums, Capability::AtomicPut];
    // AtomicReplace, SpaceInfo, Hardlinks, ServerCopy, Ownership
    for (server, instance, offers) in [
        ("o103", "default", [true, true, true, true, true]),
        ("o103", "noext", [false, false, false, false, false]),
        ("o96", "default", [true, true, true, true, true]),
        ("o89", "default", [true, true, true, false, false]),
    ] {
        let mut sftp = password_session(&s, server, instance).await;
        let caps = sftp.capabilities();
        for cap in always {
            assert!(caps.has(cap), "{server} {instance}: {cap:?}");
        }
        for cap in never {
            assert!(!caps.has(cap), "{server} {instance}: {cap:?}");
        }
        assert!(caps.checksum_algorithms.is_empty());
        let got = [
            Capability::AtomicReplace,
            Capability::SpaceInfo,
            Capability::Hardlinks,
            Capability::ServerCopy,
            Capability::Ownership,
        ]
        .map(|cap| caps.has(cap));
        assert_eq!(got, offers, "{server} {instance}");
        sftp.disconnect().await;
        assert!(sftp.capabilities().flags.is_empty(), "{server} {instance}: after disconnect");
    }
}

/// Directory operations as the server's disk shows them, on OpenSSH with its extensions and without them.
#[tokio::test]
async fn files_on_the_servers_disk() {
    let Some(s) = servers() else { return };
    for instance in ["default", "noext"] {
        let mut sftp = password_session(&s, "o103", instance).await;
        let dir = unique("netvfs-rs/files");
        let disk = format!("/home/alice/{dir}");
        let at = |name: &str| format!("{dir}/{name}");
        let on_disk = |name: &str| format!("{disk}/{name}");
        sftp.make_dir(b"netvfs-rs", false, &c()).await.unwrap();
        sftp.make_dir(dir.as_bytes(), true, &c()).await.unwrap();
        assert_eq!(
            sftp.make_dir(dir.as_bytes(), true, &c()).await.unwrap_err().name,
            ErrorName::AlreadyExists
        );

        // Upload with a mode and a time; download ranges.
        let data: Vec<u8> = (0..300_000u32).map(|i| i.wrapping_mul(131).to_le_bytes()[1]).collect();
        let options = WriteOptions {
            create_mode: Some(0o640),
            mtime_ms: Some(1_000_000_000_000),
            ..Default::default()
        };
        put(&mut sftp, &at("data"), &data, &options).await.unwrap();
        assert_eq!(
            s.text("o103", &format!("stat -c '%a %s %Y' '{}'", on_disk("data"))),
            "640 300000 1000000000"
        );
        assert_eq!(
            put(&mut sftp, &at("data"), b"x", &options).await.unwrap_err().name,
            ErrorName::AlreadyExists
        );
        assert_eq!(get(&mut sftp, &at("data"), 1000, Some(70_000)).await.unwrap(), &data[1000..71_000]);
        assert_eq!(get(&mut sftp, &at("data"), 299_990, None).await.unwrap(), &data[299_990..]);
        let truncate = WriteOptions { disposition: Disposition::Truncate, ..Default::default() };
        put(&mut sftp, &at("small"), b"small", &truncate).await.unwrap();
        put(&mut sftp, &at("small"), b"tiny", &truncate).await.unwrap();
        assert_eq!(s.text("o103", &format!("cat '{}'", on_disk("small"))), "tiny");

        // Handles: reads at offsets, a resumed write.
        let mut reader = sftp.open_read(at("data").as_bytes(), &c()).await.unwrap();
        assert_eq!(reader.size(), Some(300_000));
        let mut buf = vec![0u8; 5000];
        let n = reader.read(123_456, &mut buf, &c()).await.unwrap();
        assert_eq!(&buf[..n], &data[123_456..123_456 + n]);
        assert!(n > 0);
        reader.close(&c()).await.unwrap();
        let resume =
            WriteOptions { disposition: Disposition::Resume, resume_offset: 4, ..Default::default() };
        let mut writer = sftp.open_write(at("small").as_bytes(), &resume, &c()).await.unwrap();
        writer.write(b"-er", &c()).await.unwrap();
        assert_eq!(writer.position(), 7);
        writer.commit(&c()).await.unwrap();
        assert_eq!(s.text("o103", &format!("cat '{}'", on_disk("small"))), "tiny-er");

        // Renames: NoReplace keeps the target; Replace replaces a file.
        let kept =
            sftp.rename(at("small").as_bytes(), at("data").as_bytes(), RenameMode::NoReplace, &c()).await;
        assert_eq!(kept.unwrap_err().name, ErrorName::AlreadyExists);
        assert_eq!(s.text("o103", &format!("stat -c %s '{}'", on_disk("data"))), "300000");
        sftp.rename(at("small").as_bytes(), at("data").as_bytes(), RenameMode::Replace, &c()).await.unwrap();
        assert_eq!(s.text("o103", &format!("cat '{}'", on_disk("data"))), "tiny-er");
        sftp.make_dir(at("sub").as_bytes(), true, &c()).await.unwrap();
        let onto_folder =
            sftp.rename(at("data").as_bytes(), at("sub").as_bytes(), RenameMode::Replace, &c()).await;
        assert_eq!(onto_folder.unwrap_err().name, ErrorName::AlreadyExists);

        // SYMLINK in OpenSSH's order lands as asked.
        sftp.make_symlink(b"../sub dir/target", at("link").as_bytes(), &c()).await.unwrap();
        assert_eq!(s.text("o103", &format!("readlink '{}'", on_disk("link"))), "../sub dir/target");
        assert_eq!(sftp.read_link(at("link").as_bytes(), &c()).await.unwrap(), b"../sub dir/target");
        let link = sftp.stat(at("link").as_bytes(), false, &c()).await.unwrap();
        assert_eq!(link.kind, EntryType::Symlink);
        assert_eq!(sftp.stat(at("link").as_bytes(), true, &c()).await.unwrap_err().name, ErrorName::NotFound);

        // Modes and times.
        let changes = Attributes { mode: Some(0o604), mtime_ms: Some(1_200_000_000_000), atime_ms: None };
        sftp.set_attributes(at("data").as_bytes(), &changes, &c()).await.unwrap();
        assert_eq!(s.text("o103", &format!("stat -c '%a %Y' '{}'", on_disk("data"))), "604 1200000000");
        let entry = sftp.stat(at("data").as_bytes(), true, &c()).await.unwrap();
        assert_eq!((entry.mode, entry.mtime_ms, entry.size), (Some(0o604), Some(1_200_000_000_000), Some(7)));

        // Listing: names, types, no "." or "..".
        let mut entries = Entries::default();
        let options = ListOptions { batch_size: 2, resolve_symlink_types: true };
        sftp.list(dir.as_bytes(), options, &mut entries, &c()).await.unwrap();
        let mut names: Vec<(Vec<u8>, EntryType)> =
            entries.0.iter().map(|e| (e.name.clone(), e.kind)).collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            names,
            [
                (b"data".to_vec(), EntryType::File),
                (b"link".to_vec(), EntryType::Symlink),
                (b"sub".to_vec(), EntryType::Directory),
            ]
        );

        // Extensions where offered, Unsupported where not.
        let caps = sftp.capabilities();
        let hard = sftp.make_hardlink(at("data").as_bytes(), at("hard").as_bytes(), &c()).await;
        let space = sftp.space_info(dir.as_bytes(), &c()).await;
        let copied =
            sftp.copy(at("data").as_bytes(), at("copy").as_bytes(), false, RenameMode::NoReplace, &c()).await;
        if instance == "default" {
            hard.unwrap();
            assert_eq!(s.text("o103", &format!("stat -c %h '{}'", on_disk("hard"))), "2");
            let space = space.unwrap();
            assert!(space.total.unwrap() > 0 && space.free.unwrap() <= space.total.unwrap());
            copied.unwrap();
            assert_eq!(s.text("o103", &format!("cat '{}'", on_disk("copy"))), "tiny-er");
            assert!(caps.has(Capability::Ownership));
            assert_eq!((entry.owner.as_str(), entry.group.as_str()), ("alice", "alice"));
        } else {
            for (what, result) in [("hardlink", hard), ("copy", copied)] {
                assert_eq!(result.unwrap_err().name, ErrorName::Unsupported, "{what}");
            }
            assert_eq!(space.unwrap_err().name, ErrorName::Unsupported);
            assert_eq!((entry.owner.as_str(), entry.group.as_str()), ("", ""));
        }

        // Removal: a folder is not a file, a full folder stays.
        assert_eq!(
            sftp.remove_file(at("sub").as_bytes(), &c()).await.unwrap_err().name,
            ErrorName::IsADirectory
        );
        put(&mut sftp, &at("sub/inner"), b"i", &WriteOptions::default()).await.unwrap();
        assert_eq!(
            sftp.remove_dir(at("sub").as_bytes(), &c()).await.unwrap_err().name,
            ErrorName::DirectoryNotEmpty
        );
        sftp.remove_file(at("sub/inner").as_bytes(), &c()).await.unwrap();
        sftp.remove_dir(at("sub").as_bytes(), &c()).await.unwrap();
        sftp.remove_file(at("link").as_bytes(), &c()).await.unwrap();
        assert_eq!(s.text("o103", &format!("ls -A '{disk}' | grep -c sub || true")), "0");
        s.exec("o103", &format!("rm -rf '{disk}'"), b"");
    }
}

/// Cancel ends a request the server holds back (sftpproxy.py --hold-file), the connection goes on; a request
/// timeout ends it too.
#[tokio::test]
async fn cancel_and_request_timeout() {
    let Some(s) = servers() else { return };
    // Not left over from a run that stopped half way.
    s.exec("o89", "rm -f /tmp/hold", b"");
    let mut sftp = password_session(&s, "o89", "hold").await;
    s.exec("o89", "touch /tmp/hold", b"");
    let token = CancelToken::new();
    let started = Instant::now();
    let (held, ()) = tokio::join!(sftp.stat(b"", true, &token), async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        token.cancel();
    });
    let elapsed = started.elapsed();
    s.exec("o89", "rm -f /tmp/hold", b"");
    assert_eq!(held.unwrap_err().name, ErrorName::Canceled);
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    // The held reply comes, and is not taken for the next request's.
    let entry = sftp.stat(b"/", true, &c()).await.unwrap();
    assert_eq!(entry.kind, EntryType::Directory);
    sftp.keep_alive(&c()).await.unwrap();

    let mut p = s.params("o89", "hold", "alice", None);
    p.request_timeout_ms = 1500;
    let mut sftp = sign_in(&p, &s.credentials("alice")).await.unwrap();
    s.exec("o89", "touch /tmp/hold", b"");
    let started = Instant::now();
    let held = sftp.stat(b"", true, &c()).await;
    let elapsed = started.elapsed();
    s.exec("o89", "rm -f /tmp/hold", b"");
    assert_eq!(held.unwrap_err().name, ErrorName::Timeout);
    assert!(elapsed >= Duration::from_millis(1400) && elapsed < Duration::from_secs(5), "{elapsed:?}");
}

/// Refusals after sign-in: no session (MaxSessions 0), no SFTP subsystem.
/// A dropped connection is ConnectionLost.
#[tokio::test]
async fn sessions_and_lost_connections() {
    let Some(s) = servers() else { return };
    let named = |r: Result<Sftp, Status>| r.err().map(|e| (e.name, e.message));
    let refused = sign_in(&s.params("o96", "default", "nosession", None), &s.credentials("nosession")).await;
    let expected = "The server allows no further session on this connection".to_owned();
    assert_eq!(named(refused), Some((ErrorName::TooManyConnections, expected)));
    let refused = sign_in(&s.params("o103", "nosftp", "alice", None), &s.credentials("alice")).await;
    assert_eq!(
        named(refused),
        Some((ErrorName::Unsupported, "SFTP is not enabled for this user".to_owned()))
    );

    let mut sftp =
        sign_in(&s.params("o96", "default", "carol", None), &s.credentials("carol")).await.unwrap();
    sftp.keep_alive(&c()).await.unwrap();
    s.exec(
        "o96",
        "for p in /proc/[0-9]*; do [ \"$(stat -c %U $p)\" = carol ] && kill -9 ${p#/proc/}; done; true",
        b"",
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(sftp.keep_alive(&c()).await.unwrap_err().name, ErrorName::ConnectionLost);
    assert_eq!(sftp.stat(b"", true, &c()).await.unwrap_err().name, ErrorName::ConnectionLost);

    // A session that ends says so (DISCONNECT, as ssh does) before the
    // connection closes.
    let line = "Received disconnect from";
    let before = s.log_count("o96", "default", line);
    let mut sftp = password_session(&s, "o96", "default").await;
    sftp.disconnect().await;
    let mut seen = before;
    for _ in 0..50 {
        seen = s.log_count("o96", "default", line);
        if seen > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen > before, "the server saw no DISCONNECT");
}
