// SPDX-License-Identifier: LGPL-2.1-or-later
//! Test support shared by the unit and the integration tests (feature
//! `testing`): temporary folders and a private session bus.
//!
//! A failing set-up is a failing test, so these helpers panic.
#![allow(clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

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

/// A private `dbus-daemon`, stopped on drop.
#[derive(Debug)]
pub struct TestBus {
    child: Child,
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
        let spawned = Command::new(program)
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // It complains when it cannot raise its fd limit.
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!("dbus-daemon: {e}"),
        };
        let address = read_address(&mut child);
        Some(Self { child, address, _dir: dir })
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

impl Drop for TestBus {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
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
