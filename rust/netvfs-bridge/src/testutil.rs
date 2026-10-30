// SPDX-License-Identifier: LGPL-2.1-or-later
//! Test support (feature `testing`): temporary folders, child processes that do not outlive their test, private session bus. Set-up failure fails the test: helpers panic.
#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Fresh folder below the temporary folder, removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// Creates a new folder, never a leftover of a killed test with the same pid.
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

/// Child process of a test. SIGKILLed and reaped on drop; the kernel kills it when the starting thread ends (`PR_SET_PDEATHSIG`). Start from the test's own thread.
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

    /// Waits at most `timeout` for the process: how it ended.
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

fn deadline(timeout: Duration) -> Instant {
    Instant::now().checked_add(timeout).expect("a deadline")
}

impl Drop for TestChild {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

/// Whether a stream socket listens at `path`, read from `/proc/net/unix` (a socket file exists after `bind`, before `listen`).
#[must_use]
pub fn listening(path: &Path) -> bool {
    std::fs::read_to_string("/proc/net/unix").is_ok_and(|table| listening_in(&table, path))
}

fn listening_in(table: &str, path: &Path) -> bool {
    table.lines().skip(1).any(|row| {
        let fields: Vec<&str> = row.split_whitespace().collect();
        let [_, _, _, flags, kind, _, _, name] = fields[..] else { return false };
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        flags & 0x10000 != 0 && kind == "0001" && Path::new(name) == path
    })
}

/// Command that runs `program` as socket activation would: `listener` at fd 3, `LISTEN_FDS=1`, `LISTEN_PID` set by a shell to its own pid before exec (unknown before the fork). Must not remove the two variables.
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

/// Private bus config: anyone may own any name and send anything.
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

/// Private `dbus-daemon`, stopped on drop (or with the starting thread, see [`TestChild`]).
#[derive(Debug)]
pub struct TestBus {
    _child: TestChild,
    address: String,
    _dir: TempDir,
}

impl TestBus {
    /// Starts the bus; `None` without `dbus-daemon` (caller skips).
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

    /// Bus address as `DBUS_SESSION_BUS_ADDRESS` would carry it.
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
    fn listening_means_listen_was_called() {
        let dir = TempDir::default();
        let stream = dir.path().join("stream.sock");
        let datagram = dir.path().join("datagram.sock");
        assert!(!listening(&stream));
        let listener = std::os::unix::net::UnixListener::bind(&stream).unwrap();
        assert!(listening(&stream));
        let _bound = std::os::unix::net::UnixDatagram::bind(&datagram).unwrap();
        assert!(datagram.exists() && !listening(&datagram));
        drop(listener);
        assert!(!listening(&stream));
    }

    #[test]
    fn listening_reads_flags_type_and_path() {
        let head = "Num       RefCount Protocol Flags    Type St Inode Path\n";
        let line = |flags: &str, kind: &str, path: &str| {
            format!("0000000000000000: 00000002 00000000 {flags} {kind} 01 4242 {path}\n")
        };
        let row = |flags: &str, kind: &str, path: &str| format!("{head}{}", line(flags, kind, path));
        let at = Path::new("/t/bridge.sock");
        assert!(listening_in(&row("00010000", "0001", "/t/bridge.sock"), at));
        assert!(!listening_in(&row("00000000", "0001", "/t/bridge.sock"), at));
        assert!(!listening_in(&row("00010000", "0002", "/t/bridge.sock"), at));
        assert!(!listening_in(&row("00010000", "0001", "/t/other.sock"), at));
        assert!(!listening_in(
            &format!("{head}0000000000000000: 00000002 00000000 00010000 0001 01 4242\n"),
            at
        ));
        assert!(!listening_in(&row("00010000", "0001", "/t/bridge.sock"), Path::new("/t/bridge")));
        assert!(!listening_in(&line("00010000", "0001", "/t/bridge.sock"), at));
    }

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
        let installed = std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join("dbus-daemon").is_file()));
        assert_eq!(TestBus::start().is_some(), installed);
        assert!(TestBus::start_program(Path::new("/nonexistent/dbus-daemon")).is_none());
    }

    #[test]
    #[should_panic(expected = "dbus-daemon: ")]
    fn other_failures_fail() {
        let _ = TestBus::start_program(Path::new("/"));
    }
}
