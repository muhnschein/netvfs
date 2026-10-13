// SPDX-License-Identifier: LGPL-2.1-or-later
//! The confinement (SPEC-v2 XB-2a), each part applied to a fresh probe
//! process (src/bin/probe.rs), and the helper's own run.
#![cfg(feature = "probe")]
#![allow(clippy::unwrap_used)]
// The setgid copies need ids and file system flags from libc.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PROBE: &str = env!("CARGO_BIN_EXE_netvfs-accounts-probe");
const HELPER: &str = env!("CARGO_BIN_EXE_netvfs-accounts");
const NO_LANDLOCK: i32 = 77;
const NO_SECCOMP: i32 = 99;

/// Writes to the test's stderr, which the harness shows when a test fails.
/// The one place this file writes to stderr.
#[allow(clippy::print_stderr)]
fn note(text: &str) {
    eprintln!("{text}");
}

/// A fresh folder below the temporary one, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let path =
            std::env::temp_dir().join(format!("netvfs-accounts-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn probe(args: &[&str]) -> i32 {
    let output = Command::new(PROBE).args(args).stdin(Stdio::null()).output().unwrap();
    note(String::from_utf8_lossy(&output.stderr).trim_end());
    output.status.code().unwrap_or(-1)
}

#[test]
fn descriptors() {
    // A caller's closed stdio becomes /dev/null, so that no file the helper
    // opens receives its answer; other inherited descriptors close.
    let status = Command::new("/bin/sh")
        .args(["-c", "exec \"$0\" descriptors 3 3</dev/null 0<&- 2>&-", PROBE])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn process_state() {
    assert_eq!(probe(&["process-state"]), 0);
}

#[test]
fn syscalls() {
    let dir = TempDir::new("syscalls");
    match probe(&["syscalls", dir.path().to_str().unwrap()]) {
        NO_SECCOMP => note("skipped: no seccomp filters on this kernel or architecture"),
        status => assert_eq!(status, 0),
    }
}

#[test]
fn filesystem() {
    let allowed = TempDir::new("allowed");
    let denied = TempDir::new("denied");
    std::fs::write(denied.path().join("secret"), b"secret").unwrap();
    match probe(&["filesystem", allowed.path().to_str().unwrap(), denied.path().to_str().unwrap()]) {
        NO_LANDLOCK => note("skipped: no Landlock on this kernel"),
        status => assert_eq!(status, 0),
    }
    assert!(!denied.path().join("planted").exists());
}

#[test]
fn set_id_environment() {
    assert_eq!(probe(&["set-id-environment"]), 0);
}

#[test]
fn group() {
    assert_eq!(probe(&["group"]), 0);
}

/// A gid other than the effective one that this process may give a file:
/// any as root, else one of its supplementary groups.
fn other_group() -> Option<libc::gid_t> {
    // SAFETY: plain id calls; the buffer holds `count` entries.
    unsafe {
        let effective = libc::getegid();
        if libc::geteuid() == 0 {
            return Some(if effective == 65534 { 65533 } else { 65534 });
        }
        let count = libc::getgroups(0, std::ptr::null_mut());
        let mut groups = vec![0; usize::try_from(count).ok()?];
        let count = libc::getgroups(count, groups.as_mut_ptr());
        groups.truncate(usize::try_from(count).ok()?);
        groups.into_iter().find(|g| *g != effective)
    }
}

/// A setgid copy of `binary` with another group, None (the test skips) when
/// there is no such group or the file system ignores set-id bits.
fn set_id_copy(binary: &str, name: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let gid = other_group()?;
    let copy = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::remove_file(&copy).ok();
    std::fs::copy(binary, &copy).unwrap();
    let path = std::ffi::CString::new(copy.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid, NUL-terminated path and a zeroed statvfs to fill.
    let nosuid = unsafe {
        let mut fs: libc::statvfs = std::mem::zeroed();
        libc::statvfs(path.as_ptr(), &raw mut fs) != 0 || fs.f_flag & libc::ST_NOSUID != 0
    };
    if nosuid || std::os::unix::fs::chown(&copy, None, Some(gid)).is_err() {
        std::fs::remove_file(&copy).ok();
        return None;
    }
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o2755)).unwrap();
    Some(copy)
}

/// Runs a fresh copy. Another test's child forked while the copy was being
/// written holds it open for writing until that child's exec: ETXTBSY.
fn run_copy(command: &mut Command) -> std::process::Output {
    for _ in 0..100 {
        match command.output() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result.unwrap(),
        }
    }
    command.output().unwrap()
}

#[test]
fn set_id_group() {
    // A real set-id start: the group it brings is given up for good.
    let Some(copy) = set_id_copy(PROBE, "probe") else {
        note("skipped: no other group, or a nosuid file system");
        return;
    };
    let output = run_copy(Command::new(&copy).args(["group", "set-id"]));
    std::fs::remove_file(&copy).ok();
    note(String::from_utf8_lossy(&output.stderr).trim_end());
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn set_id_helper() {
    // The whole set-id start (environment, home, confinement, group) up to
    // an answer, for a request that reads no database.
    let Some(copy) = set_id_copy(HELPER, "helper") else {
        note("skipped: no other group, or a nosuid file system");
        return;
    };
    let output = run_copy(Command::new(&copy).arg("bogus").stdin(Stdio::null()));
    std::fs::remove_file(&copy).ok();
    note(String::from_utf8_lossy(&output.stderr).trim_end());
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.starts_with(&header(12)));
}

#[test]
fn unknown_part() {
    assert_eq!(probe(&["bogus"]), 2);
}

fn helper(args: &[&str], accounts: &Path) -> (Option<i32>, Vec<u8>) {
    let output = Command::new(HELPER)
        .args(args)
        .env("ACCOUNTS", accounts)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (output.status.code(), output.stdout)
}

/// An answer's header: magic, error, and the message's length.
fn header(error: u8) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 17];
    bytes.extend_from_slice(b"netvfs-accounts/1");
    bytes.extend_from_slice(&[0, 0, 0, error]);
    bytes
}

#[test]
fn helper_answers_without_a_database() {
    // No database yet: no accounts, and none is created.
    let dir = TempDir::new("helper");
    let missing = dir.path().join("missing");
    let (status, answer) = helper(&["list"], &missing);
    assert_eq!(status, Some(0));
    let mut empty = header(0);
    empty.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
    assert_eq!(answer, empty);
    let (status, answer) = helper(&["attention", "1", "auth-failed"], &missing);
    assert_eq!(status, Some(0));
    assert!(answer.starts_with(&header(9)));
    assert!(!missing.exists());

    let (status, answer) = helper(&["bogus"], &missing);
    assert_eq!(status, Some(0));
    assert!(answer.starts_with(&header(12)));

    // A file where the folder should be: the setgid hint.
    std::fs::write(dir.path().join("file"), b"").unwrap();
    let (status, answer) = helper(&["list"], &dir.path().join("file/accounts"));
    assert_eq!(status, Some(0));
    assert!(answer.starts_with(&header(8)));
}

#[test]
fn helper_reports_an_answer_it_cannot_write() {
    let dir = TempDir::new("full");
    let status = Command::new("/bin/sh")
        .args(["-c", "exec \"$0\" list >/dev/full", HELPER])
        .env("ACCOUNTS", dir.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}
