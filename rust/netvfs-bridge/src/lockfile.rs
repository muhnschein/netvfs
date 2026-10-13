// SPDX-License-Identifier: LGPL-2.1-or-later
//! A lock file compatible with Qt's `QLockFile`, which `QSettings` takes as
//! `<file>.lock` around every write (the account UI writes `bridge.conf`).
//!
//! As `QLockFile` on Unix: the lock is the file itself, created with
//! `O_EXCL` and holding `<pid>\n<process name>\n<host name>\n`; the holder
//! keeps it `flock`ed so that nobody removes it while it lives. A lock is
//! stale when its process is gone (or runs another program) on this host,
//! or when it is older than 30 s; a stale lock is removed under
//! `<file>.rmlock`, and only when its `flock` can be taken. Qt 5.6 reads the
//! first three lines, Qt 5.10 and later also take a lock without the two
//! machine and boot id lines they write themselves.

use crate::sys::lock::{lock_exclusive_nonblocking, process_exists};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// `QLockFile`'s default stale lock time.
pub const STALE_AFTER: Duration = Duration::from_secs(30);
/// `QLockFile::lock`'s first pause; it doubles up to 5 s.
const FIRST_PAUSE: Duration = Duration::from_millis(100);
const MAX_PAUSE: Duration = Duration::from_secs(5);
/// How many stale `.rmlock` levels are cleared (Qt goes on as long as each
/// level is stale).
const RMLOCK_LEVELS: u32 = 4;

/// A held lock; released (removed) on drop.
#[derive(Debug)]
pub struct LockFile {
    path: PathBuf,
    // Holds the flock until the file is gone.
    _file: File,
}

impl LockFile {
    /// Takes the lock at `path`, waiting at most `timeout` (`QLockFile::
    /// tryLock(timeout)`).
    ///
    /// # Errors
    /// `TimedOut` when someone else holds it all along; an I/O error when
    /// the lock file cannot be created at all.
    pub fn lock(path: &Path, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now().checked_add(timeout);
        let mut pause = FIRST_PAUSE;
        loop {
            if let Some(lock) = Self::try_lock(path)? {
                return Ok(lock);
            }
            let left = deadline.map_or(Duration::ZERO, |d| d.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("{} is locked", path.display())));
            }
            std::thread::sleep(pause.min(left));
            pause = pause.saturating_mul(2).min(MAX_PAUSE);
        }
    }

    /// One attempt, removing a stale lock first (`QLockFile::tryLock(0)`);
    /// `None` when someone holds it.
    ///
    /// # Errors
    /// When the lock file cannot be created for another reason than that
    /// it exists.
    pub fn try_lock(path: &Path) -> io::Result<Option<Self>> {
        try_lock_at(path, RMLOCK_LEVELS)
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        // Removed while still flocked, so that nobody takes it for stale in
        // between (Qt closes first).
        fs::remove_file(&self.path).ok();
    }
}

/// `tryLock` with `depth` levels of `.rmlock` for stale locks.
fn try_lock_at(path: &Path, depth: u32) -> io::Result<Option<LockFile>> {
    if let Some(lock) = create(path)? {
        return Ok(Some(lock));
    }
    if !is_stale(path) {
        return Ok(None);
    }
    let Some(depth) = depth.checked_sub(1) else { return Ok(None) };
    let mut rmlock = path.as_os_str().to_os_string();
    rmlock.push(".rmlock");
    // Only one process removes it; the check is repeated under the rmlock,
    // which is itself a lock file that a crashed remover may have left.
    let removed = match try_lock_at(Path::new(&rmlock), depth)? {
        Some(_guard) => is_stale(path) && remove_stale(path),
        None => false,
    };
    if removed { create(path) } else { Ok(None) }
}

/// Creates the lock file exclusively; `None` when it exists. Unlike Qt's
/// `0666` less the umask, only the owner may read or write it: the account
/// UI and the bridge run as the same user, and others need not see the pid.
fn create(path: &Path) -> io::Result<Option<LockFile>> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
        Err(e) => return Err(e),
    };
    // As Qt: a lock without flock still works, it is only easier to steal.
    if let Err(e) = lock_exclusive_nonblocking(file.as_fd()) {
        crate::log::debug(format_args!("No flock on {}: {e}", path.display()));
    }
    let written = file.write_all(contents().as_bytes()).and_then(|()| file.sync_data());
    if let Err(e) = written {
        fs::remove_file(path).ok();
        return Err(e);
    }
    Ok(Some(LockFile { path: path.to_owned(), _file: file }))
}

/// `QLockFilePrivate::lockFileContents` of Qt 5.6.
fn contents() -> String {
    format!("{}\n{}\n{}\n", std::process::id(), process_name(None).unwrap_or_default(), host_name())
}

/// `QSysInfo::machineHostName()`.
fn host_name() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim_end_matches('\n').to_owned())
        .unwrap_or_default()
}

/// `processNameByPid`: the file name of `/proc/<pid>/exe` (ours for
/// `None`), without " (deleted)".
fn process_name(pid: Option<i32>) -> Option<String> {
    let link =
        pid.map_or_else(|| PathBuf::from("/proc/self/exe"), |p| PathBuf::from(format!("/proc/{p}/exe")));
    let target = fs::read_link(link).ok()?;
    let name = target.file_name()?.to_string_lossy().into_owned();
    Some(name.strip_suffix(" (deleted)").map(str::to_owned).unwrap_or(name))
}

/// What a lock file says about its holder.
#[derive(Debug, PartialEq, Eq)]
struct Holder {
    pid: i32,
    name: String,
    host: String,
}

/// `getLockInfo`: pid, application and host lines.
fn holder(content: &[u8]) -> Option<Holder> {
    let mut lines = content.split(|b| *b == b'\n');
    let pid_line = lines.next()?;
    let name = String::from_utf8_lossy(lines.next()?).into_owned();
    let host = String::from_utf8_lossy(lines.next()?).into_owned();
    let pid: i32 = std::str::from_utf8(pid_line).ok()?.trim_ascii().parse().ok()?;
    (pid > 0).then_some(Holder { pid, name, host })
}

/// `QLockFilePrivate::isApparentlyStale`.
fn is_stale(path: &Path) -> bool {
    if let Some(holder) = fs::read(path).ok().as_deref().and_then(holder)
        && (holder.host.is_empty() || holder.host == host_name())
        && !holder_runs(&holder)
    {
        return true;
    }
    fs::metadata(path).and_then(|m| m.modified()).is_ok_and(|modified| is_old(modified, SystemTime::now()))
}

/// Whether a lock modified at `modified` is older than [`STALE_AFTER`] at
/// `now` (also when its time is that far in the future, as in Qt).
fn is_old(modified: SystemTime, now: SystemTime) -> bool {
    now.duration_since(modified).unwrap_or_else(|e| e.duration()) > STALE_AFTER
}

/// Whether the holder's process still runs the program it named.
fn holder_runs(holder: &Holder) -> bool {
    if !process_exists(holder.pid) {
        return false;
    }
    let named =
        Path::new(&holder.name).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    process_name(Some(holder.pid)).is_none_or(|running| running == named)
}

/// `removeStaleLock`: unlinks the file only if nobody holds its flock.
fn remove_stale(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().write(true).custom_flags(libc::O_CLOEXEC).open(path) else {
        return false;
    };
    lock_exclusive_nonblocking(file.as_fd()).is_ok() && fs::remove_file(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    /// The host and program names, not from the code under test.
    fn real_host() -> String {
        fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim_end().to_owned()
    }

    fn real_name() -> String {
        std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned()
    }

    fn set_age(path: &Path, age: Duration) {
        let file = File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now().checked_sub(age).unwrap()).unwrap();
    }

    #[test]
    fn exclusive_until_dropped() {
        let dir = TempDir::new();
        let path = dir.join("bridge.conf.lock");
        let lock = LockFile::try_lock(&path).unwrap().unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, format!("{}\n{}\n{}\n", std::process::id(), real_name(), real_host()));
        assert!(!real_host().is_empty());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // Held and alive: neither taken nor stale, also when old (flock).
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        set_age(&path, Duration::from_mins(1));
        assert!(is_stale(&path));
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        let started = Instant::now();
        assert_eq!(
            LockFile::lock(&path, Duration::from_millis(250)).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        drop(lock);
        assert!(!path.exists());
        drop(LockFile::lock(&path, Duration::ZERO).unwrap());
    }

    #[test]
    fn waits_for_a_release() {
        let dir = TempDir::new();
        let path = dir.join("l");
        let lock = LockFile::try_lock(&path).unwrap().unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(lock);
        });
        let started = Instant::now();
        let again = LockFile::lock(&path, Duration::from_secs(5)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(150));
        releaser.join().unwrap();
        drop(again);
    }

    #[test]
    fn stale_locks_are_taken() {
        let dir = TempDir::new();
        let path = dir.join("l");
        // A crashed holder on this host (no process with that pid).
        fs::write(&path, format!("{}\nqsg\n{}\n", i32::MAX, real_host())).unwrap();
        assert!(is_stale(&path));
        let lock = LockFile::try_lock(&path).unwrap().unwrap();
        assert!(fs::read_to_string(&path).unwrap().starts_with(&format!("{}\n", std::process::id())));
        assert!(!dir.join("l.rmlock").exists());
        drop(lock);
        // A live process running another program: the pid was reused.
        fs::write(&path, format!("{}\nnot-this-program\n\n", std::process::id())).unwrap();
        assert!(is_stale(&path));
        // Ours, named with a path as Qt 5.6's applicationName may be.
        let me = real_name();
        fs::write(&path, format!("{}\n/some/where/{me}\n{}\n", std::process::id(), real_host())).unwrap();
        assert!(!is_stale(&path));
        // Another host: only its age counts.
        fs::write(&path, format!("{}\nqsg\nelsewhere\n", i32::MAX)).unwrap();
        assert!(!is_stale(&path));
        set_age(&path, Duration::from_secs(31));
        assert!(is_stale(&path));
        // Unreadable content (a lock being written): only its age counts.
        fs::write(&path, b"").unwrap();
        assert!(!is_stale(&path));
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        set_age(&path, Duration::from_secs(29));
        assert!(!is_stale(&path));
        set_age(&path, Duration::from_secs(31));
        drop(LockFile::try_lock(&path).unwrap().unwrap());
        assert!(!is_stale(&dir.join("missing")));
    }

    #[test]
    fn stale_but_flocked_is_kept() {
        let dir = TempDir::new();
        let path = dir.join("l");
        fs::write(&path, format!("{}\nqsg\n{}\n", i32::MAX, real_host())).unwrap();
        let holder = File::open(&path).unwrap();
        lock_exclusive_nonblocking(holder.as_fd()).unwrap();
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        assert!(path.exists());
        // Someone else removing it right now: no second remover.
        drop(holder);
        let rmlock = LockFile::try_lock(&dir.join("l.rmlock")).unwrap().unwrap();
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        drop(rmlock);
        assert!(LockFile::try_lock(&path).unwrap().is_some());
    }

    #[test]
    fn stale_rmlocks_are_cleared() {
        let dir = TempDir::new();
        let path = dir.join("l");
        let crashed = format!("{}\nqsg\n{}\n", i32::MAX, real_host());
        // A remover crashed under the rmlock, and before it another one.
        for name in ["l", "l.rmlock", "l.rmlock.rmlock"] {
            fs::write(dir.join(name), &crashed).unwrap();
        }
        let lock = LockFile::try_lock(&path).unwrap().unwrap();
        assert!(!dir.join("l.rmlock").exists() && !dir.join("l.rmlock.rmlock").exists());
        drop(lock);
        // A live rmlock: the stale lock stays until it is released.
        fs::write(&path, &crashed).unwrap();
        let remover = LockFile::try_lock(&dir.join("l.rmlock")).unwrap().unwrap();
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        drop(remover);
        // Levels beyond the limit are left alone.
        let mut name = String::from("m");
        for _ in 0..=RMLOCK_LEVELS {
            fs::write(dir.join(&name), &crashed).unwrap();
            name.push_str(".rmlock");
        }
        assert!(LockFile::try_lock(&dir.join("m")).unwrap().is_none());
        fs::remove_file(dir.join(name.strip_suffix(".rmlock").unwrap())).unwrap();
        assert!(LockFile::try_lock(&dir.join("m")).unwrap().is_some());
    }

    #[test]
    fn age_limit() {
        let now = SystemTime::now();
        let at = |d: Duration| now.checked_sub(d).unwrap();
        assert!(!is_old(at(STALE_AFTER), now));
        assert!(is_old(at(STALE_AFTER + Duration::from_nanos(1)), now));
        assert!(!is_old(now, now));
        assert!(is_old(now + Duration::from_secs(31), now));
        assert!(!is_old(now + Duration::from_secs(29), now));
    }

    #[test]
    fn holder_lines() {
        assert_eq!(
            holder(b"12\napp\nhost\nmachine\nboot\n"),
            Some(Holder { pid: 12, name: "app".into(), host: "host".into() })
        );
        assert_eq!(
            holder(b" 12\napp\n\n"),
            Some(Holder { pid: 12, name: "app".into(), host: String::new() })
        );
        for bad in [&b""[..], b"12\napp", b"x\na\nb\n", b"0\na\nb\n", b"-3\na\nb\n", b"99999999999\na\nb\n"] {
            assert_eq!(holder(bad), None, "{bad:?}");
        }
    }

    /// Against Qt's own QLockFile: the qsettings-golden tool that
    /// tests/data/qsettings/generate.sh builds, named by
    /// `NETVFS_QSETTINGS_GOLDEN` (skipped without it).
    #[test]
    fn qlockfile_interop() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let Some(tool) = std::env::var_os("NETVFS_QSETTINGS_GOLDEN") else { return };
        let dir = TempDir::new();
        let path = dir.join("bridge.conf.lock");
        // Qt holds it: we wait in vain.
        let mut qt = Command::new(&tool)
            .arg("lock")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(qt.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(line, "locked\n");
        assert!(LockFile::try_lock(&path).unwrap().is_none());
        drop(qt.stdin.take());
        assert!(qt.wait().unwrap().success());
        // We hold it: Qt cannot take it, also when it is old.
        let lock = LockFile::try_lock(&path).unwrap().unwrap();
        let qt_try = || Command::new(&tool).arg("trylock").arg(&path).status().unwrap().success();
        assert!(!qt_try());
        set_age(&path, Duration::from_mins(1));
        assert!(!qt_try());
        drop(lock);
        // Ours, left by a crash: Qt takes it as stale.
        fs::write(&path, format!("{}\n{}\n{}\n", i32::MAX, real_name(), real_host())).unwrap();
        assert!(qt_try());
    }

    #[test]
    fn errors_other_than_existing() {
        let dir = TempDir::new();
        assert_eq!(LockFile::try_lock(&dir.join("missing/l")).unwrap_err().kind(), io::ErrorKind::NotFound);
        LockFile::lock(&dir.join("missing/l"), Duration::from_secs(1)).unwrap_err();
    }
}
