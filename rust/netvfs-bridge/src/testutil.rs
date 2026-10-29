// SPDX-License-Identifier: LGPL-2.1-or-later
//! Test support shared by the unit and the integration tests (feature
//! `testing`): temporary folders, child processes that do not outlive
//! their test, and a private session bus.
//!
//! A failing set-up is a failing test, so these helpers panic.
#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// A fresh folder below the system's temporary folder, removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates the folder: a new one, never a leftover of a test process
    /// that was killed (and had the same process id).
    #[must_use]
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("nvb-test-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("temporary folder {}: {e}", path.display()),
            }
        }
    }

    /// The folder.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// `name` below the folder.
    #[must_use]
    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `data` to `name` below the folder (creating folders).
    pub fn write(&self, name: &str, data: impl AsRef<[u8]>) -> PathBuf {
        let path = self.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("folder");
        }
        std::fs::write(&path, data).expect("file");
        path
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A child process of a test. It is killed (SIGKILL) and reaped when
/// dropped, and the kernel kills it when the thread that started it ends
/// (`PR_SET_PDEATHSIG`): a test that panics, times out or is killed leaves
/// no process behind. Start it from the test's own thread.
#[derive(Debug)]
pub struct TestChild(Child);

impl TestChild {
    /// Spawns `command`'s program.
    ///
    /// # Errors
    /// As [`Command::spawn`].
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        crate::sys::child::kill_with_parent(command).spawn().map(Self)
    }

    /// The process.
    pub const fn child(&mut self) -> &mut Child {
        &mut self.0
    }

    /// Waits at most `timeout` for the process to end: how it ended.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let end = deadline(timeout);
        loop {
            match self.0.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() >= end => return None,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("try_wait: {e}"),
            }
        }
    }
}

/// `timeout` from now.
fn deadline(timeout: Duration) -> Instant {
    Instant::now().checked_add(timeout).expect("a deadline")
}

impl Drop for TestChild {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

/// A command that runs `program` as systemd's socket activation would
/// (`sd_listen_fds`): `listener` at fd 3, `LISTEN_FDS=1`, and `LISTEN_PID`
/// the process's own pid, which a shell sets before it execs `program` (the
/// pid is unknown before the fork). Arguments and environment are the
/// caller's, except that it must not remove the two variables.
#[must_use]
pub fn socket_activated(program: &Path, listener: OwnedFd) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "LISTEN_PID=$$; export LISTEN_PID; exec \"$0\" \"$@\""])
        .arg(program)
        .env("LISTEN_FDS", "1");
    crate::sys::child::place_listener(&mut command, listener);
    command
}

/// The configuration of the private bus: anyone may own any name and send
/// anything.
const BUS_CONFIG: &str = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=@DIR@</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#;

/// A private `dbus-daemon`, stopped on drop (or with the thread that
/// started it, see [`TestChild`]).
#[derive(Debug)]
pub struct TestBus {
    _child: TestChild,
    address: String,
    _dir: TempDir,
}

impl TestBus {
    /// Starts the bus; `None` when `dbus-daemon` is not installed (the
    /// caller skips its test).
    #[must_use]
    pub fn start() -> Option<Self> {
        Self::start_program(Path::new("dbus-daemon"))
    }

    fn start_program(program: &Path) -> Option<Self> {
        let dir = TempDir::new();
        let config = dir.write("bus.conf", BUS_CONFIG.replace("@DIR@", &dir.path().to_string_lossy()));
        let spawned = TestChild::spawn(
            Command::new(program)
                .arg(format!("--config-file={}", config.display()))
                .args(["--nofork", "--print-address=1"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                // It complains when it cannot raise its fd limit.
                .stderr(Stdio::null()),
        );
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!("dbus-daemon: {e}"),
        };
        let address = read_address(child.child());
        Some(Self { _child: child, address, _dir: dir })
    }

    /// The bus address, as `DBUS_SESSION_BUS_ADDRESS` would carry it.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// A new connection to the bus.
    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address())
            .expect("bus address")
            .build()
            .await
            .expect("bus connection")
    }
}

/// The first line `dbus-daemon --print-address=1` prints.
fn read_address(child: &mut Child) -> String {
    let mut address = String::new();
    BufReader::new(child.stdout.take().expect("piped stdout")).read_line(&mut address).expect("bus address");
    let address = address.trim_end().to_owned();
    assert!(!address.is_empty(), "dbus-daemon printed no address");
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_are_removed() {
        let dir = TempDir::default();
        let path = dir.write("a/b", "x");
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        let kept = dir.path().to_owned();
        drop(dir);
        assert!(!kept.exists());
    }

    #[test]
    fn leftovers_are_skipped() {
        // Folders a killed test process with this process id left behind.
        let mut planted = Vec::new();
        for n in 0..8 {
            let path = std::env::temp_dir().join(format!("nvb-test-{}-{n}", std::process::id()));
            if std::fs::create_dir(&path).is_ok() {
                std::fs::write(path.join("stale"), "x").unwrap();
                planted.push(path);
            }
        }
        let dir = TempDir::new();
        assert!(!planted.iter().any(|p| p == dir.path()));
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        for path in planted {
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn children_are_killed_when_dropped() {
        let mut child = TestChild::spawn(Command::new("sleep").arg("60")).unwrap();
        assert_eq!(child.wait_timeout(Duration::from_millis(50)), None);
        let pid = i32::try_from(child.child().id()).unwrap();
        drop(child);
        // Reaped as well: the pid names no process (nor a zombie) any more.
        assert!(!crate::sys::lock::process_exists(pid));
        let mut child = TestChild::spawn(Command::new("sh").args(["-c", "exit 3"])).unwrap();
        assert_eq!(child.wait_timeout(Duration::from_secs(10)).unwrap().code(), Some(3));
        TestChild::spawn(&mut Command::new("/nonexistent/program")).unwrap_err();
    }

    #[test]
    fn socket_activation_as_systemd_does_it() {
        use std::io::Read as _;
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut command = socket_activated(Path::new("/bin/sh"), OwnedFd::from(theirs));
        command.args(["-c", "echo \"$$ $LISTEN_PID $LISTEN_FDS\" >&3"]);
        let mut child = TestChild::spawn(&mut command).unwrap();
        drop(command);
        let pid = child.child().id();
        assert!(child.wait_timeout(Duration::from_secs(10)).unwrap().success());
        let mut got = String::new();
        ours.read_to_string(&mut got).unwrap();
        assert_eq!(got, format!("{pid} {pid} 1\n"));
    }

    #[test]
    fn bus_or_skip() {
        // Installed (as where these tests run): a bus, not a skipped test.
        let installed = std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join("dbus-daemon").is_file()));
        assert_eq!(TestBus::start().is_some(), installed);
        assert!(TestBus::start_program(Path::new("/nonexistent/dbus-daemon")).is_none());
    }

    #[test]
    #[should_panic(expected = "dbus-daemon: ")]
    fn other_failures_fail() {
        // Not a program: a broken set-up, not a missing daemon.
        let _ = TestBus::start_program(Path::new("/"));
    }
}
