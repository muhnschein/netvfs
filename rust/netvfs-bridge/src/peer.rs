// SPDX-License-Identifier: LGPL-2.1-or-later
//! SPEC-v2 XB-5: who is on the other end of the socket (port of
//! `src/bridge/lib/peercheck.cpp`).
//!
//! 1. `SO_PEERCRED` of the connected socket: the uid must be the bridge's own.
//! 2. The peer's executable must be the registered one. `/proc/<pid>/exe` is
//!    opened (the magic link opens the file the peer runs, across mount
//!    namespaces, so a path cannot fake it) and compared with `Executable` by
//!    identity (device and inode). Sailjail starts apps with firejail
//!    `--private-bin`, which runs a copy of the binary from a tmpfs
//!    bind-mounted over `/usr/bin`: another inode. A different file is
//!    therefore accepted when it has the same size and the same bytes, read
//!    from the descriptor opened in step 3's window (in chunks, bounded
//!    memory).
//! 3. Pid reuse: the pid in `SO_PEERCRED` belongs to the process that
//!    connected. If that process exited and its pid was reused before the
//!    check, the check must not succeed. Where the kernel has pidfds
//!    (`SO_PEERPIDFD`, Linux 6.5, names the connecting process itself;
//!    `pidfd_open`, Linux 5.3, pins the pid from then on) the check holds a
//!    pidfd while it reads `/proc` and verifies afterwards that the pidfd's
//!    process is still alive with that pid (`Pid:` line of
//!    `/proc/self/fdinfo/<pidfd>`). In every case the process start time
//!    (`/proc/<pid>/stat` field 22) must be the same before and after opening
//!    `exe` and must not be later than the moment of the check, so a process
//!    started after the connection cannot pass for it.
//!
//! `/proc`, the credentials and the clock are injectable for tests
//! ([`Environment`]).

use crate::status::Status;
use crate::sys;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

pub use crate::sys::peer::PeerCredentials;

/// proc(5): field 22 of `/proc/<pid>/stat` is `starttime`, in clock ticks
/// since boot.
const START_TIME_FIELD: usize = 22;
/// Largest `/proc` file read (stat, fdinfo, uptime).
const MAX_PROC_FILE_BYTES: u64 = 4096;
/// Chunk size of the executable comparison.
const COMPARE_CHUNK_BYTES: usize = 64 * 1024;

/// Credentials of a connected socket.
pub type CredentialsFn = Box<dyn Fn(BorrowedFd<'_>) -> Option<PeerCredentials> + Send + Sync>;
/// `pidfd_open`.
pub type OpenPidfdFn = Box<dyn Fn(i32) -> Option<OwnedFd> + Send + Sync>;
/// Clock ticks since boot "now".
pub type TicksFn = Box<dyn Fn() -> Option<i64> + Send + Sync>;
/// A hook between the two start time reads.
pub type HookFn = Box<dyn Fn() + Send + Sync>;

/// What the check reads from the system; injectable for tests.
pub struct Environment {
    /// Where `/proc` is.
    pub proc_root: PathBuf,
    /// The bridge's uid.
    pub own_uid: u32,
    /// Credentials of a connected socket; default `SO_PEERCRED` (+ `SO_PEERPIDFD`).
    pub credentials: CredentialsFn,
    /// `pidfd_open()`; default the syscall, `None` where it is missing.
    pub open_pidfd: OpenPidfdFn,
    /// Clock ticks since boot "now" (to compare with the start time);
    /// default `/proc/uptime` times `sysconf(_SC_CLK_TCK)`.
    pub boot_ticks_now: TicksFn,
    /// Called after `exe` was opened, between the first and the second start
    /// time read (tests simulate pid reuse there).
    pub after_exe_read: Option<HookFn>,
}

impl Environment {
    /// The real system: `/proc`, this process's euid, the syscalls.
    #[must_use]
    pub fn system() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            own_uid: sys::peer::effective_uid(),
            credentials: Box::new(|fd| sys::peer::credentials(fd).ok()),
            open_pidfd: Box::new(sys::peer::pidfd_open),
            boot_ticks_now: Box::new(system_boot_ticks_now),
            after_exe_read: None,
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::system()
    }
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Environment")
            .field("proc_root", &self.proc_root)
            .field("own_uid", &self.own_uid)
            .finish_non_exhaustive()
    }
}

/// The XB-5 check against one registered executable.
#[derive(Debug)]
pub struct PeerChecker {
    executable: PathBuf,
    env: Environment,
}

fn refused(why: String) -> Status {
    Status::permission_denied(why)
}

impl PeerChecker {
    /// A checker for the consumer's registered `executable`, on the real system.
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self::with_environment(executable, Environment::system())
    }

    /// A checker with an injected environment.
    pub fn with_environment(executable: impl Into<PathBuf>, env: Environment) -> Self {
        Self { executable: executable.into(), env }
    }

    /// The registered executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Checks the peer of the connected socket `socket`.
    ///
    /// # Errors
    /// `PermissionDenied` with the reason (for the warning log).
    pub fn check(&self, socket: BorrowedFd<'_>) -> Result<(), Status> {
        let credentials =
            (self.env.credentials)(socket).ok_or_else(|| refused("no peer credentials".to_owned()))?;
        self.check_credentials(credentials)
    }

    /// The same for already known credentials (their pidfd is closed after).
    ///
    /// # Errors
    /// `PermissionDenied` with the reason.
    pub fn check_credentials(&self, credentials: PeerCredentials) -> Result<(), Status> {
        let PeerCredentials { pid, uid, pidfd } = credentials;
        if uid != self.env.own_uid {
            return Err(refused(format!("peer uid {uid} is not the bridge's uid")));
        }
        if pid <= 0 {
            return Err(refused("no peer process".to_owned()));
        }
        let pidfd = pidfd.or_else(|| (self.env.open_pidfd)(pid));
        self.check_process(pid, pidfd.as_ref())
    }

    fn proc_path(&self, pid: i32, leaf: &str) -> PathBuf {
        self.env.proc_root.join(pid.to_string()).join(leaf)
    }

    fn start_time(&self, pid: i32) -> Option<i64> {
        parse_start_time(&read_small_file(&self.proc_path(pid, "stat"))?)
    }

    fn pidfd_alive(&self, pidfd: &OwnedFd, pid: i32) -> bool {
        let path = self.env.proc_root.join("self/fdinfo").join(pidfd.as_raw_fd().to_string());
        read_small_file(&path).and_then(|info| parse_fdinfo_pid(&info)) == Some(i64::from(pid))
    }

    fn check_process(&self, pid: i32, pidfd: Option<&OwnedFd>) -> Result<(), Status> {
        let reused = || refused(format!("peer pid {pid} was reused"));
        let before = self.start_time(pid).ok_or_else(|| refused(format!("peer process {pid} is gone")))?;
        if (self.env.boot_ticks_now)().is_some_and(|now| before > now) {
            return Err(reused());
        }
        // Opened, not only stat()ed, inside the start time window: the open
        // file stays the one this process runs, and its content is compared
        // from it.
        let exe = open_with_metadata(&self.proc_path(pid, "exe"));
        if let Some(hook) = &self.env.after_exe_read {
            hook();
        }
        if self.start_time(pid) != Some(before) {
            return Err(reused());
        }
        if pidfd.is_some_and(|fd| !self.pidfd_alive(fd, pid)) {
            return Err(refused(format!("peer process {pid} exited during the check")));
        }
        let (exe, exe_meta) =
            exe.ok_or_else(|| refused(format!("cannot read the executable of peer {pid}")))?;
        let (expected, expected_meta) = open_with_metadata(&self.executable)
            .ok_or_else(|| refused("the registered executable cannot be read".to_owned()))?;
        if exe_meta.dev() == expected_meta.dev() && exe_meta.ino() == expected_meta.ino() {
            return Ok(());
        }
        // Sailjail's firejail --private-bin runs a copy of the executable from
        // a tmpfs: another file, so the same bytes are required instead.
        if exe_meta.len() != expected_meta.len() || !same_content(exe, expected) {
            return Err(refused(format!("peer {pid} runs another executable")));
        }
        Ok(())
    }
}

fn open_with_metadata(path: &Path) -> Option<(File, std::fs::Metadata)> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    Some((file, meta))
}

fn read_small_file(path: &Path) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path).ok()?.take(MAX_PROC_FILE_BYTES).read_to_end(&mut data).ok()?;
    Some(data)
}

/// Field 22 of a `/proc/<pid>/stat` line: "pid (comm) state ..." where comm
/// may contain spaces and parentheses.
fn parse_start_time(stat: &[u8]) -> Option<i64> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = stat.get(close.checked_add(2)?..)?;
    // The first field after the comm is field 3 (state).
    let index = START_TIME_FIELD.checked_sub(3)?;
    let field = rest.split(|&b| b == b' ').nth(index)?;
    std::str::from_utf8(field).ok()?.trim_end().parse().ok()
}

/// The `Pid:` of a pidfd's fdinfo (-1 once the process has exited).
fn parse_fdinfo_pid(info: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(info).ok()?;
    text.lines().find_map(|line| line.strip_prefix("Pid:")).and_then(|v| v.trim().parse().ok())
}

/// `/proc/uptime` in clock ticks: "<seconds>.<fraction> ..." parsed as
/// integers (as a double, 0.29 * 100 truncates to 28, a tick before the start
/// time of a peer that started in that tick, which was then refused as a
/// reused pid).
fn uptime_ticks(uptime: &str, hz: i64) -> Option<i64> {
    let field = uptime.split(' ').next()?;
    let (seconds, fraction) = field.split_once('.').unwrap_or((field, ""));
    // The fraction as nanoseconds: padded or cut to nine digits.
    let nanos_text: String = fraction.chars().chain(std::iter::repeat('0')).take(9).collect();
    let seconds: i64 = seconds.parse().ok()?;
    let nanos: i64 = nanos_text.parse().ok()?;
    if seconds < 0 || nanos < 0 {
        return None;
    }
    seconds.checked_mul(hz)?.checked_add(nanos.checked_mul(hz)? / 1_000_000_000)
}

fn system_boot_ticks_now() -> Option<i64> {
    let uptime = read_small_file(Path::new("/proc/uptime"))?;
    uptime_ticks(std::str::from_utf8(&uptime).ok()?, sys::peer::clock_ticks_per_second()?)
}

/// Reads up to `buffer.len()` bytes; fewer only at the end of the file.
fn read_fully(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut done = 0;
    while let Some(rest) = buffer.get_mut(done..) {
        if rest.is_empty() {
            break;
        }
        match file.read(rest) {
            Ok(0) => break,
            Ok(n) => done = done.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

/// Byte for byte, in chunks (bounded memory), from the start.
fn same_content(mut a: File, mut b: File) -> bool {
    let mut left = vec![0u8; COMPARE_CHUNK_BYTES];
    let mut right = vec![0u8; COMPARE_CHUNK_BYTES];
    loop {
        let (Ok(n), Ok(m)) = (read_fully(&mut a, &mut left), read_fully(&mut b, &mut right)) else {
            return false;
        };
        if n != m || left.get(..n) != right.get(..m) {
            return false;
        }
        if n == 0 {
            return true;
        }
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
