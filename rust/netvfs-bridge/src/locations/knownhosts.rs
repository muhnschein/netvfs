// SPDX-License-Identifier: LGPL-2.1-or-later
//! Identities the user accepted for ad-hoc locations of one consumer, in `~/.local/share/netvfs/bridge/<id>/known_hosts`. One line per endpoint, sorted: `<provider>://<host>:<port> <pin>`. Mode 0600, replaced atomically.
//!
//! Thread-safe: workers read pins while establishing connections, the identity hook writes an accepted one. Reads and writes block.

use crate::savefile::{self, Mode};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

const MAX_FILE_BYTES: u64 = 1 << 20;

/// One consumer's known hosts.
#[derive(Debug)]
pub struct KnownHosts {
    path: PathBuf,
    // None until first used.
    pins: Mutex<Option<HashMap<String, String>>>,
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && !key.contains([' ', '\n'])
}

impl KnownHosts {
    /// The known hosts in `path`, read on first use.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), pins: Mutex::new(None) }
    }

    /// The file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pin stored for `key` (`<provider>://<host>:<port>`), empty if none.
    #[must_use]
    pub fn pin(&self, key: &str) -> String {
        self.with_pins(|pins| pins.get(key).cloned().unwrap_or_default())
    }

    /// Stores `pin` for `key` and saves the file.
    #[must_use]
    pub fn set_pin(&self, key: &str, pin: &str) -> bool {
        if !is_valid_key(key) || pin.is_empty() || pin.contains('\n') {
            return false;
        }
        self.with_pins(|pins| {
            pins.insert(key.to_owned(), pin.to_owned());
            self.save(pins)
        })
    }

    /// Forgets `key` (`ForgetAdHoc`).
    #[must_use]
    pub fn remove(&self, key: &str) -> bool {
        self.with_pins(|pins| pins.remove(key).is_none() || self.save(pins))
    }

    fn with_pins<T>(&self, f: impl FnOnce(&mut HashMap<String, String>) -> T) -> T {
        let mut guard = self.pins.lock().unwrap_or_else(PoisonError::into_inner);
        f(guard.get_or_insert_with(|| load(&self.path)))
    }

    fn save(&self, pins: &HashMap<String, String>) -> bool {
        let mut keys: Vec<&String> = pins.keys().collect();
        // Sorted by UTF-16 code units.
        keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let mut text = String::new();
        for key in keys {
            let pin = pins.get(key).map(String::as_str).unwrap_or_default();
            writeln!(text, "{key} {pin}").ok();
        }
        let saved = self
            .path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| savefile::save(&self.path, text.as_bytes(), Mode::Exactly(0o600)));
        if let Err(e) = &saved {
            crate::log::warning(format_args!("Cannot save {}: {e}", self.path.display()));
        }
        saved.is_ok()
    }
}

fn load(path: &Path) -> HashMap<String, String> {
    let mut data = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        file.take(MAX_FILE_BYTES).read_to_end(&mut data).unwrap_or_default();
    }
    data.split(|b| *b == b'\n')
        .filter_map(|line| {
            let space = line.iter().position(|b| *b == b' ').filter(|p| *p > 0)?;
            let (key, pin) = line.split_at(space);
            let pin = String::from_utf8_lossy(pin.get(1..).unwrap_or_default()).trim().to_owned();
            Some((String::from_utf8_lossy(key).into_owned(), pin))
        })
        .collect()
}

impl super::connector::PinStore for KnownHosts {
    fn pin(&self, key: &str) -> String {
        Self::pin(self, key)
    }

    fn set_pin(&self, key: &str, pin: &str) -> bool {
        Self::set_pin(self, key, pin)
    }

    fn remove(&self, key: &str) -> bool {
        Self::remove(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn pins() {
        let dir = TempDir::new();
        let path = dir.join("b/known_hosts");
        {
            let hosts = KnownHosts::new(&path);
            assert_eq!(hosts.pin("sftp://h:0").len(), 0);
            assert!(hosts.set_pin("sftp://h:0", "ssh-ed25519 AAAA"));
            assert!(!hosts.set_pin("bad key", "x"));
        }
        let reread = KnownHosts::new(&path);
        assert_eq!(reread.pin("sftp://h:0"), "ssh-ed25519 AAAA");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(reread.remove("sftp://h:0"));
        assert_eq!(KnownHosts::new(&path).pin("sftp://h:0").len(), 0);
        assert_eq!(reread.path(), path);
    }

    #[test]
    fn known_hosts_are_a_pin_store() {
        use crate::locations::connector::PinStore;
        let dir = TempDir::new();
        let store: &dyn PinStore = &KnownHosts::new(dir.join("known_hosts"));
        assert_eq!(store.pin("fake://h:0").len(), 0);
        assert!(store.set_pin("fake://h:0", "ssh-ed25519 AAAA"));
        assert!(!store.set_pin("bad key", "x"));
        assert_eq!(store.pin("fake://h:0"), "ssh-ed25519 AAAA");
        assert!(store.remove("fake://h:0"));
        assert_eq!(store.pin("fake://h:0").len(), 0);
        std::fs::remove_file(dir.join("known_hosts")).unwrap();
        std::fs::create_dir(dir.join("known_hosts")).unwrap();
        let blocked: &dyn PinStore = &KnownHosts::new(dir.join("known_hosts"));
        assert!(!blocked.set_pin("fake://h:0", "x"));
    }

    #[test]
    fn file_format() {
        let dir = TempDir::new();
        let path = dir.write(
            "known_hosts",
            "smb://b:445 sha256/x\n sftp://lead:22 p\nnospace\nsftp://a:22   ssh-rsa AAA  \r\nsmb://b:445 later\n",
        );
        let hosts = KnownHosts::new(&path);
        assert_eq!(hosts.pin("sftp://a:22"), "ssh-rsa AAA");
        assert_eq!(hosts.pin("smb://b:445"), "later");
        assert_eq!(hosts.pin("nospace"), "");
        assert_eq!(hosts.pin(""), "");
        assert!(hosts.set_pin("\u{1f600}://c:1", "z"));
        assert!(hosts.set_pin("\u{ffff}://c:1", "y"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "sftp://a:22 ssh-rsa AAA\nsmb://b:445 later\n\u{1f600}://c:1 z\n\u{ffff}://c:1 y\n"
        );
    }

    #[test]
    fn refusals_and_failures() {
        let dir = TempDir::new();
        let hosts = KnownHosts::new(dir.join("k"));
        for (key, pin) in [("", "p"), ("a b", "p"), ("a\nb", "p"), ("k", ""), ("k", "a\nb")] {
            assert!(!hosts.set_pin(key, pin), "{key:?} {pin:?}");
        }
        assert!(!dir.join("k").exists());
        assert!(hosts.remove("absent"));
        assert!(!dir.join("k").exists());
        std::fs::write(dir.join("f"), b"").unwrap();
        let broken = KnownHosts::new(dir.join("f/k"));
        assert!(!broken.set_pin("a", "b"));
        assert_eq!(broken.pin("a"), "b");
        assert!(!broken.remove("a"));
    }

    #[test]
    fn reads_the_first_mib_only() {
        let dir = TempDir::new();
        let mut text = "#".repeat((1 << 20) - 6);
        text.push_str("\na b\nc d\n");
        let path = dir.write("k", text);
        let hosts = KnownHosts::new(path);
        assert_eq!(hosts.pin("a"), "b");
        assert_eq!(hosts.pin("c"), "");
        let dir2 = TempDir::new();
        let mut fits = "#".repeat((1 << 20) - 5);
        fits.push_str("\na b");
        assert_eq!(KnownHosts::new(dir2.write("k", fits)).pin("a"), "b");
    }

    #[test]
    fn shared_between_threads() {
        let dir = TempDir::new();
        let hosts = std::sync::Arc::new(KnownHosts::new(dir.join("k")));
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let hosts = std::sync::Arc::clone(&hosts);
                std::thread::spawn(move || assert!(hosts.set_pin(&format!("k{i}"), "p")))
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(std::fs::read_to_string(dir.join("k")).unwrap(), "k0 p\nk1 p\nk2 p\nk3 p\n");
    }
}
