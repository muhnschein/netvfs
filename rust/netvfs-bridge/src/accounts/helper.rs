// SPDX-License-Identifier: LGPL-2.1-or-later
//! The bridge's account directory: everything through netvfs-accounts
//! (SPEC-v2 XB-2a), started once per request:
//!
//! ```text
//! netvfs-accounts list                          the Files accounts (XA-1)
//! netvfs-accounts files <id>                    what a connection to a listed
//!                                               account needs, policy checked (XA-4)
//! netvfs-accounts attention <id> <state> [pin]  records auth-failed or
//!                                               server-identity-changed (XB-14)
//! ```
//!
//! Each run happens on the blocking pool, gets 10 s and is killed after
//! that; only the first MiB of its answer is read. Its warnings go to the
//! bridge's stderr.

use super::qds::{decode_files, decode_list, decode_status};
use super::{AccountDirectory, AccountLocation, Attention, FilesAccess};
use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// How long a run may take.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// How much of an answer is read.
pub const MAX_ANSWER_BYTES: u64 = 1 << 20;
/// How often a run that closed its output is checked for its exit.
const EXIT_POLL: Duration = Duration::from_millis(5);

/// Called after the helper recorded an attention state.
pub type ChangeHook = Arc<dyn Fn() + Send + Sync>;

/// The account directory of the bridge.
#[derive(Clone)]
pub struct HelperDirectory {
    program: PathBuf,
    timeout: Duration,
    changed: Option<ChangeHook>,
}

impl std::fmt::Debug for HelperDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperDirectory")
            .field("program", &self.program)
            .field("timeout", &self.timeout)
            .field("changed", &self.changed.is_some())
            .finish()
    }
}

impl HelperDirectory {
    /// Runs `program` (normally [`crate::config::Env::accounts_helper`]).
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self { program: program.into(), timeout: TIMEOUT, changed: None }
    }

    /// Calls `changed` after each recorded attention state: the helper's own
    /// `AccountChanged` may not reach the bus (it is set-id), so the owner
    /// lists again without waiting for it.
    #[must_use]
    pub fn on_change(mut self, changed: ChangeHook) -> Self {
        self.changed = Some(changed);
        self
    }

    /// Another time limit than [`TIMEOUT`] (tests).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The helper's answer to `arguments`.
    async fn run(&self, arguments: Vec<String>) -> Result<Vec<u8>, Status> {
        let (program, timeout) = (self.program.clone(), self.timeout);
        tokio::task::spawn_blocking(move || run(&program, &arguments, timeout))
            .await
            .unwrap_or_else(|e| Err(Status::new(ErrorName::Internal, e.to_string())))
    }

    async fn try_list(&self) -> Result<Vec<AccountLocation>, Status> {
        decode_list(&self.run(vec!["list".to_owned()]).await?)
    }

    async fn try_set_attention(&self, id: i32, attention: Attention, pin: &str) -> Result<(), Status> {
        let mut arguments = vec!["attention".to_owned(), id.to_string(), attention.as_str().to_owned()];
        if !pin.is_empty() {
            arguments.push(pin.to_owned());
        }
        decode_status(&self.run(arguments).await?)
    }
}

impl AccountDirectory for HelperDirectory {
    async fn list(&self) -> Vec<AccountLocation> {
        self.try_list().await.unwrap_or_else(|status| {
            crate::log::warning(format_args!("Cannot list the accounts, none is listed: {status}"));
            Vec::new()
        })
    }

    async fn files(&self, id: i32) -> Result<FilesAccess, Status> {
        let answer = self.run(vec!["files".to_owned(), id.to_string()]).await;
        answer.and_then(|a| decode_files(&a)).inspect_err(|status| {
            crate::log::debug(format_args!("Account {id} for Files: {status}"));
        })
    }

    async fn set_attention(&self, id: i32, attention: Attention, pin: &str) {
        match self.try_set_attention(id, attention, pin).await {
            Ok(()) => {
                if let Some(changed) = &self.changed {
                    changed();
                }
            }
            Err(status) => crate::log::warning(format_args!("Cannot record the attention state: {status}")),
        }
    }
}

/// Runs `program` with `arguments`: its answer once it ended with status
/// 0, within `timeout`.
fn run(program: &Path, arguments: &[String], timeout: Duration) -> Result<Vec<u8>, Status> {
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            Status::new(ErrorName::Unsupported, format!("Cannot start {}: {e}", program.display()))
        })?;
    let (sender, answer) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        // Detached: it ends with the last writer of the pipe, which may be
        // a process the helper started.
        std::thread::spawn(move || sender.send(read_capped(stdout)).ok());
    }
    let finished = answer.recv_timeout(timeout).ok().and_then(|answer| {
        let left = timeout.saturating_sub(started.elapsed());
        wait_for_exit(&mut child, left).map(|status| (status, answer))
    });
    match finished {
        Some((status, answer)) if status.success() => Ok(answer),
        Some(_) => Err(Status::new(ErrorName::ProtocolError, format!("{} failed", program.display()))),
        None => {
            child.kill().ok();
            child.wait().ok();
            Err(Status::new(ErrorName::Timeout, format!("{} did not answer in time", program.display())))
        }
    }
}

/// The exit status of `child`, if it ends within `timeout`.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now().checked_add(timeout)?;
    loop {
        if let Some(status) = child.try_wait().ok()? {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(EXIT_POLL);
    }
}

/// The first [`MAX_ANSWER_BYTES`] of `output`; the rest is read and
/// dropped, so that the writer does not block.
fn read_capped(mut output: impl Read) -> Vec<u8> {
    let mut answer = Vec::new();
    // A failed read ends the answer: it is then too short to decode.
    output.by_ref().take(MAX_ANSWER_BYTES).read_to_end(&mut answer).ok();
    io::copy(&mut output, &mut io::sink()).ok();
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::qds::Writer;
    use crate::log::{Level, capture};
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A helper that records its arguments and answers with `answer`.
    fn script(dir: &TempDir, answer: &[u8]) -> PathBuf {
        dir.write("answer", answer);
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{0}/args'\nexec cat '{0}/answer'\n",
            dir.path().display()
        );
        executable(dir, "helper", &body)
    }

    fn executable(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        let path = dir.write(name, body);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn args(dir: &TempDir) -> String {
        std::fs::read_to_string(dir.join("args")).unwrap_or_default()
    }

    fn golden(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/data/accounts/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[tokio::test]
    async fn lists() {
        // tst_BridgeAccounts::directoryLists
        let dir = TempDir::new();
        let directory = HelperDirectory::new(script(&dir, &golden("list.bin")));
        let accounts = directory.list().await;
        assert_eq!(accounts.iter().map(|a| a.account_id).collect::<Vec<_>>(), [3, 4, i32::MAX]);
        assert_eq!(accounts[0].params.host, "files.example");
        assert_eq!(args(&dir), "list\n");
        // A failure of the helper lists nothing.
        dir.write("answer", golden("not-found.bin"));
        assert_eq!(directory.try_list().await.unwrap_err().to_string(), "NotFound: No such account");
        assert!(directory.list().await.is_empty());
    }

    #[tokio::test]
    async fn failures_list_nothing() {
        // tst_BridgeAccounts::directoryFailures
        let missing = HelperDirectory::new("/nonexistent/netvfs-accounts");
        let status = missing.try_list().await.unwrap_err();
        assert_eq!(status.name, ErrorName::Unsupported);
        assert!(status.message.starts_with("Cannot start /nonexistent/netvfs-accounts: "), "{status}");
        assert!(missing.list().await.is_empty());
        let failing = HelperDirectory::new("/bin/false");
        assert_eq!(failing.try_list().await.unwrap_err().to_string(), "ProtocolError: /bin/false failed");
        capture::start();
        assert!(failing.list().await.is_empty());
        let warning = "Cannot list the accounts, none is listed: ProtocolError: /bin/false failed";
        assert_eq!(capture::take(), [(Level::Warning, warning.to_owned())]);
        let silent = HelperDirectory::new("/bin/true");
        assert_eq!(
            silent.try_list().await.unwrap_err().to_string(),
            "ProtocolError: netvfs-accounts gave a malformed answer"
        );
        // A crash is a failure, whatever it wrote.
        let dir = TempDir::new();
        let crash = executable(
            &dir,
            "crash",
            &format!("#!/bin/sh\ncat '{}'\nkill -SEGV $$\n", dir.write("a", golden("list.bin")).display()),
        );
        let status = HelperDirectory::new(&crash).try_list().await.unwrap_err();
        assert_eq!(status.message, format!("{} failed", crash.display()));
        // A good answer with a failed exit is a failure too.
        let exit =
            executable(&dir, "exit", &format!("#!/bin/sh\ncat '{}'\nexit 3\n", dir.join("a").display()));
        assert_eq!(HelperDirectory::new(&exit).try_list().await.unwrap_err().name, ErrorName::ProtocolError);
    }

    #[tokio::test]
    async fn timeout_kills() {
        let dir = TempDir::new();
        let pid = dir.join("pid");
        let slow =
            executable(&dir, "slow", &format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n", pid.display()));
        let directory = HelperDirectory::new(&slow).with_timeout(Duration::from_millis(300));
        let started = Instant::now();
        let status = directory.try_list().await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(status.to_string(), format!("Timeout: {} did not answer in time", slow.display()));
        let pid = std::fs::read_to_string(&pid).unwrap();
        assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists(), "the helper still runs");

        // Output closed but still running: the exit is waited for, within
        // the limit.
        let closes = executable(&dir, "closes", "#!/bin/sh\nexec >&-\nexec sleep 30\n");
        let directory = HelperDirectory::new(&closes).with_timeout(Duration::from_millis(300));
        assert_eq!(directory.try_list().await.unwrap_err().name, ErrorName::Timeout);
        // The output open in a process the helper left behind: the helper
        // has ended, but its answer never does.
        let leaves = executable(&dir, "leaves", "#!/bin/sh\nsleep 30 2>/dev/null &\n");
        let directory = HelperDirectory::new(&leaves).with_timeout(Duration::from_millis(300));
        assert_eq!(directory.try_list().await.unwrap_err().name, ErrorName::Timeout);
        // Slow but in time.
        let late = executable(
            &dir,
            "late",
            &format!("#!/bin/sh\nsleep 0.2\ncat '{}'\n", dir.write("a", golden("list-empty.bin")).display()),
        );
        let directory = HelperDirectory::new(&late).with_timeout(Duration::from_secs(5));
        assert_eq!(directory.try_list().await, Ok(vec![]));
    }

    #[tokio::test]
    async fn malformed_is_protocol_error() {
        let dir = TempDir::new();
        let malformed = "ProtocolError: netvfs-accounts gave a malformed answer";
        for answer in [b"garbage".to_vec(), golden("files.bin"), [golden("list.bin"), b"x".to_vec()].concat()]
        {
            let directory = HelperDirectory::new(script(&dir, &answer));
            assert_eq!(directory.try_list().await.unwrap_err().to_string(), malformed);
        }
        // More than a MiB: cut, so malformed, and the helper is not blocked.
        let big = executable(
            &dir,
            "big",
            &format!("#!/bin/sh\ncat '{}'\nhead -c 2000000 /dev/zero\n", dir.join("answer").display()),
        );
        dir.write("answer", golden("list-empty.bin"));
        let directory = HelperDirectory::new(&big);
        assert_eq!(directory.try_list().await.unwrap_err().to_string(), malformed);
    }

    #[test]
    fn answers_are_capped() {
        let cap = usize::try_from(MAX_ANSWER_BYTES).unwrap();
        let mut long = io::Cursor::new(vec![7_u8; cap + 10]);
        assert_eq!(read_capped(&mut long).len(), cap);
        assert_eq!(long.position(), u64::try_from(cap + 10).unwrap());
        assert_eq!(read_capped(io::Cursor::new(vec![1, 2])), [1, 2]);
    }

    #[tokio::test]
    async fn files_are_fetched() {
        // tst_BridgeAccounts::directoryFetch, up to the secret lookup.
        let dir = TempDir::new();
        let directory = HelperDirectory::new(script(&dir, &golden("files.bin")));
        let access = directory.files(3).await.unwrap();
        assert_eq!((access.credentials_id, access.secret_optional, access.params.port), (42, true, 2222));
        assert_eq!(args(&dir), "files 3\n");
        dir.write("answer", golden("not-found.bin"));
        capture::start();
        assert_eq!(directory.files(-4).await.unwrap_err().name, ErrorName::NotFound);
        let debug = "Account -4 for Files: NotFound: No such account";
        assert_eq!(capture::take(), [(Level::Debug, debug.to_owned())]);
        assert_eq!(args(&dir), "files 3\nfiles -4\n");
        let missing = HelperDirectory::new("/nonexistent/netvfs-accounts");
        assert_eq!(missing.files(3).await.unwrap_err().name, ErrorName::Unsupported);
    }

    #[tokio::test]
    async fn attention_relists() {
        // tst_BridgeAccounts::directoryAttention
        let dir = TempDir::new();
        let count = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&count);
        let directory =
            HelperDirectory::new(script(&dir, &golden("ok.bin"))).on_change(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }));
        directory.set_attention(3, Attention::AuthFailed, "").await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        directory.set_attention(3, Attention::ServerIdentityChanged, "SHA256:abc").await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(args(&dir), "attention 3 auth-failed\nattention 3 server-identity-changed SHA256:abc\n");
        // A refused write changes nothing.
        dir.write("answer", golden("not-found.bin"));
        capture::start();
        directory.set_attention(9, Attention::AuthFailed, "").await;
        let warning = "Cannot record the attention state: NotFound: No such account";
        assert_eq!(capture::take(), [(Level::Warning, warning.to_owned())]);
        let status = directory.try_set_attention(9, Attention::AuthFailed, "").await.unwrap_err();
        assert_eq!(status.to_string(), "NotFound: No such account");
        dir.write("answer", golden("list.bin"));
        assert_eq!(
            directory.try_set_attention(9, Attention::AuthFailed, "").await.unwrap_err().name,
            ErrorName::ProtocolError
        );
        directory.set_attention(9, Attention::AuthFailed, "").await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // Without a hook, nothing to call.
        dir.write("answer", golden("ok.bin"));
        HelperDirectory::new(dir.join("helper")).set_attention(3, Attention::None, "").await;
        assert!(args(&dir).ends_with("attention 3 \n"));
        let debug = format!("{directory:?}");
        assert!(debug.contains("changed: true"), "{debug}");
    }

    #[test]
    fn writer_round_trip() {
        let mut w = Writer::answer(None);
        w.i32(0);
        assert_eq!(w.into_bytes(), golden("list-empty.bin"));
    }
}
