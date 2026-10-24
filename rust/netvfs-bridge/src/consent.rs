// SPDX-License-Identifier: LGPL-2.1-or-later
//! The user's consent per consumer (SPEC-v2 XB-6) in
//! `~/.config/netvfs/bridge.conf`, `[Consent] <id>=granted|denied`, a
//! `QSettings` INI file that the account UI (Settings → Accounts → netvfs →
//! Apps using network locations) reads and writes too.
//!
//! [`ConsentStore`] reads the file on every call, so changes by the account
//! UI are seen; a write takes the `QLockFile`-compatible `bridge.conf.lock`
//! as `QSettings` does, edits the read file in place (other groups and keys
//! stay as they are) and replaces it atomically. Both block: run them on
//! the blocking pool. [`ConsentWatcher`] reports changes of the file through
//! inotify on its folder (writers replace the file).

use crate::config::is_valid_id;
use crate::ini::IniFile;
use crate::lockfile::LockFile;
use crate::savefile::{self, Mode};
use crate::sys::inotify::{Event, Inotify};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// The `[Consent]` group.
const GROUP: &str = "Consent";
/// How long a write waits for another writer's lock. `QSettings` waits
/// forever; the bridge gives up and reports the write as failed.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// A consumer's consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    /// Not decided (no entry).
    Unknown,
    /// `granted`.
    Granted,
    /// `denied`.
    Denied,
}

impl Consent {
    /// `consentToString`: `unknown`, `granted`, `denied`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    /// `consentFromString`: anything but `granted` and `denied` is unknown.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "granted" => Self::Granted,
            "denied" => Self::Denied,
            _ => Self::Unknown,
        }
    }
}

/// `bridge.conf`.
#[derive(Clone, Debug)]
pub struct ConsentStore {
    path: PathBuf,
}

impl ConsentStore {
    /// The store in `path` (`Env::consent_file()` for the user's).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The consent of consumer `id`, read now; `Unknown` for an invalid id
    /// or an unreadable file.
    #[must_use]
    pub fn consent(&self, id: &str) -> Consent {
        if !is_valid_id(id) {
            return Consent::Unknown;
        }
        let file = IniFile::parse(std::fs::read(&self.path).unwrap_or_default());
        Consent::parse(&file.string(&format!("{GROUP}/{id}")))
    }

    /// Stores the consent of consumer `id`; `Unknown` removes the entry.
    /// Nothing happens for an invalid id. A failure is logged as well.
    ///
    /// # Errors
    /// When the folder or the file cannot be written, or another writer
    /// holds the lock for [`LOCK_TIMEOUT`].
    pub fn set_consent(&self, id: &str, consent: Consent) -> io::Result<()> {
        if !is_valid_id(id) {
            return Ok(());
        }
        let written = self.write(id, consent);
        if let Err(e) = &written {
            crate::log::warning(format_args!("Cannot store the consent of {id}: {e}"));
        }
        written
    }

    fn write(&self, id: &str, consent: Consent) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut lock_path = self.path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let _lock = LockFile::lock(Path::new(&lock_path), LOCK_TIMEOUT)?;
        let current = match std::fs::read(&self.path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut file = IniFile::parse(current);
        match consent {
            Consent::Unknown => file.remove(GROUP, id),
            Consent::Granted | Consent::Denied => file.set_string(GROUP, id, consent.as_str()),
        }
        savefile::save(&self.path, file.as_bytes(), Mode::KeepOrDefault)
    }
}

/// What the watcher reacts to in the folder. A removed folder needs no
/// flag: its watch ends with `IN_IGNORED` whatever the mask.
const FOLDER_EVENTS: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR;

/// Reports changes of the consent file, as the C++ bridge's
/// `QFileSystemWatcher` on the file and its folder did: the folder is
/// watched, so that a file replaced by rename is seen; a removed folder is
/// created and watched again.
#[derive(Debug)]
pub struct ConsentWatcher {
    inotify: AsyncFd<Inotify>,
    folder: PathBuf,
    name: Vec<u8>,
    wd: i32,
}

impl ConsentWatcher {
    /// Watches the folder of `file`, creating it. Needs a tokio runtime with
    /// I/O enabled.
    ///
    /// # Errors
    /// When the folder cannot be created or watched.
    pub fn new(file: &Path) -> io::Result<Self> {
        let folder =
            file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new(".")).to_owned();
        let name = file.file_name().map(|n| n.as_bytes().to_vec()).unwrap_or_default();
        let inotify = Inotify::new()?;
        let wd = watch(&inotify, &folder)?;
        Ok(Self { inotify: inotify.register()?, folder, name, wd })
    }

    /// Waits until the file may have changed: written, replaced, removed,
    /// or its folder was. Several changes at once are one.
    ///
    /// # Errors
    /// When inotify fails, or the folder cannot be watched again.
    pub async fn changed(&mut self) -> io::Result<()> {
        loop {
            let mut ready = self.inotify.readable().await?;
            let events = match ready.try_io(|fd| fd.get_ref().read_events()) {
                Ok(events) => events?,
                Err(_would_block) => continue,
            };
            if self.relevant(&events)? {
                return Ok(());
            }
        }
    }

    /// Whether `events` concern the file; renews a lost folder watch.
    fn relevant(&mut self, events: &[Event]) -> io::Result<bool> {
        let mut changed = false;
        for event in events {
            if event.mask & libc::IN_Q_OVERFLOW != 0 {
                changed = true;
            } else if event.wd != self.wd {
                // A folder watched before it was moved away.
            } else if event.mask & (libc::IN_IGNORED | libc::IN_MOVE_SELF) != 0 {
                self.wd = watch(self.inotify.get_ref(), &self.folder)?;
                changed = true;
            } else if event.name == self.name {
                changed = true;
            }
        }
        Ok(changed)
    }
}

/// Creates `folder` and watches it (`QDir::mkpath` + `addPath`).
fn watch(inotify: &Inotify, folder: &Path) -> io::Result<i32> {
    std::fs::create_dir_all(folder)?;
    inotify.add_watch(folder, FOLDER_EVENTS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ini::tests::{dump, qt_dump};
    use crate::testutil::TempDir;

    const BRIDGE_QT: &[u8] = include_bytes!("../tests/data/qsettings/bridge-qt.conf");
    const BRIDGE_RUST_EDITED: &[u8] = include_bytes!("../tests/data/qsettings/bridge-rust-edited.conf");
    const BRIDGE_QT_EDITED_DUMP: &str = include_str!("../tests/data/qsettings/bridge-qt-edited.dump");
    const FRESH: &[u8] = include_bytes!("../tests/data/qsettings/fresh.conf");

    /// The C++ case `consent`.
    #[test]
    fn consent_round_trip() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("sub/bridge.conf"));
        assert_eq!(store.consent("lautta"), Consent::Unknown);
        store.set_consent("lautta", Consent::Granted).unwrap();
        assert_eq!(ConsentStore::new(store.path()).consent("lautta"), Consent::Granted);
        assert_eq!(store.consent("other"), Consent::Unknown);
        store.set_consent("lautta", Consent::Denied).unwrap();
        assert_eq!(store.consent("lautta"), Consent::Denied);
        store.set_consent("lautta", Consent::Unknown).unwrap();
        assert_eq!(store.consent("lautta"), Consent::Unknown);
        assert_eq!(Consent::Granted.as_str(), "granted");
        assert_eq!(Consent::Denied.as_str(), "denied");
        assert_eq!(Consent::Unknown.as_str(), "unknown");
        assert_eq!(Consent::parse("yes"), Consent::Unknown);
        assert_eq!(Consent::parse("unknown"), Consent::Unknown);
        // Invalid ids are never read or written; the lock is gone.
        store.set_consent("Bad", Consent::Granted).unwrap();
        assert_eq!(std::fs::read(store.path()).unwrap(), b"[Consent]\n");
        assert!(!dir.join("sub/bridge.conf.lock").exists());
        std::fs::write(store.path(), "[Consent]\nBad=granted\n").unwrap();
        assert_eq!(store.consent("Bad"), Consent::Unknown);
    }

    /// A file QSettings wrote (other groups, escapes, lists, types): the
    /// edits keep every other line, and Qt reads the result as it reads
    /// its own edit of the same file (generate.sh checks that).
    #[test]
    fn keeps_other_groups_and_qt_format() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("bridge.conf"));
        std::fs::write(store.path(), BRIDGE_QT).unwrap();
        assert_eq!(store.consent("lautta"), Consent::Granted);
        assert_eq!(store.consent("photos"), Consent::Denied);
        store.set_consent("lautta", Consent::Denied).unwrap();
        store.set_consent("photos", Consent::Unknown).unwrap();
        store.set_consent("new-one", Consent::Granted).unwrap();
        let written = std::fs::read(store.path()).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), String::from_utf8_lossy(BRIDGE_RUST_EDITED));
        assert_eq!(dump(&IniFile::parse(written)), qt_dump(BRIDGE_QT_EDITED_DUMP));
    }

    #[test]
    fn first_write_as_qsettings() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("netvfs/bridge.conf"));
        store.set_consent("lautta", Consent::Granted).unwrap();
        assert_eq!(std::fs::read(store.path()).unwrap(), FRESH);
    }

    #[test]
    fn writes_wait_for_the_lock() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("bridge.conf"));
        let held = LockFile::try_lock(&dir.join("bridge.conf.lock")).unwrap().unwrap();
        let writer = {
            let store = store.clone();
            std::thread::spawn(move || store.set_consent("lautta", Consent::Granted))
        };
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(store.consent("lautta"), Consent::Unknown);
        drop(held);
        writer.join().unwrap().unwrap();
        assert_eq!(store.consent("lautta"), Consent::Granted);
        assert_eq!(LOCK_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn unreadable_files_are_kept() {
        // A file that cannot be read is not replaced by a fresh one.
        let dir = TempDir::new();
        let path = dir.join("bridge.conf");
        std::os::unix::fs::symlink("bridge.conf", &path).unwrap();
        let store = ConsentStore::new(&path);
        assert_eq!(store.set_consent("x", Consent::Granted).unwrap_err().raw_os_error(), Some(libc::ELOOP));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn failures() {
        let dir = TempDir::new();
        // The folder is a file.
        std::fs::write(dir.join("f"), b"").unwrap();
        ConsentStore::new(dir.join("f/bridge.conf")).set_consent("x", Consent::Granted).unwrap_err();
        // The file is a folder: unreadable for reading and writing.
        std::fs::create_dir(dir.join("d")).unwrap();
        let store = ConsentStore::new(dir.join("d"));
        assert_eq!(store.consent("x"), Consent::Unknown);
        store.set_consent("x", Consent::Granted).unwrap_err();
    }

    #[tokio::test]
    async fn watcher_sees_writes_replacements_and_removals() {
        let dir = TempDir::new();
        let file = dir.join("netvfs/bridge.conf");
        let mut watcher = ConsentWatcher::new(&file).unwrap();
        assert!(dir.join("netvfs").is_dir());
        let store = ConsentStore::new(&file);
        store.set_consent("lautta", Consent::Granted).unwrap();
        expect_change(&mut watcher).await;
        std::fs::write(&file, b"[Consent]\nlautta=denied\n").unwrap();
        expect_change(&mut watcher).await;
        // Other files in the folder are not the consent file.
        std::fs::write(dir.join("netvfs/other"), b"x").unwrap();
        expect_quiet(&mut watcher).await;
        std::fs::remove_file(&file).unwrap();
        expect_change(&mut watcher).await;
        // The folder is removed: watched again once it is back.
        std::fs::remove_dir_all(dir.join("netvfs")).unwrap();
        expect_change(&mut watcher).await;
        assert!(dir.join("netvfs").is_dir());
        store.set_consent("lautta", Consent::Granted).unwrap();
        expect_change(&mut watcher).await;
    }

    #[tokio::test]
    async fn every_kind_of_change_is_seen() {
        let dir = TempDir::new();
        let file = dir.join("f/bridge.conf");
        dir.write("f/bridge.conf", "[Consent]\n");
        let mut watcher = ConsentWatcher::new(&file).unwrap();
        // Written in place (IN_CLOSE_WRITE).
        std::fs::OpenOptions::new().write(true).truncate(true).open(&file).unwrap();
        expect_change(&mut watcher).await;
        // Renamed away (IN_MOVED_FROM) and back (IN_MOVED_TO).
        std::fs::rename(&file, dir.join("f/away")).unwrap();
        expect_change(&mut watcher).await;
        std::fs::rename(dir.join("f/away"), &file).unwrap();
        expect_change(&mut watcher).await;
        // Removed (IN_DELETE), created as a link (IN_CREATE alone).
        std::fs::remove_file(&file).unwrap();
        expect_change(&mut watcher).await;
        std::os::unix::fs::symlink("elsewhere", &file).unwrap();
        expect_change(&mut watcher).await;
        // The folder moved away (IN_MOVE_SELF): watched again where it was.
        std::fs::rename(dir.join("f"), dir.join("g")).unwrap();
        expect_change(&mut watcher).await;
        assert!(dir.join("f").is_dir());
        std::fs::write(&file, b"").unwrap();
        expect_change(&mut watcher).await;
        // The moved folder is not watched any more.
        std::fs::remove_file(dir.join("g/bridge.conf")).unwrap();
        expect_quiet(&mut watcher).await;
    }

    async fn expect_change(watcher: &mut ConsentWatcher) {
        tokio::time::timeout(Duration::from_secs(5), watcher.changed()).await.unwrap().unwrap();
        // Let the rest of a burst arrive, then drop it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        while tokio::time::timeout(Duration::from_millis(20), watcher.changed()).await.is_ok() {}
    }

    async fn expect_quiet(watcher: &mut ConsentWatcher) {
        tokio::time::timeout(Duration::from_millis(200), watcher.changed()).await.unwrap_err();
    }

    #[test]
    fn relevant_events() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap();
        let _guard = rt.enter();
        let dir = TempDir::new();
        let mut watcher = ConsentWatcher::new(&dir.join("bridge.conf")).unwrap();
        let wd = watcher.wd;
        let event = |wd, mask, name: &[u8]| Event { wd, mask, name: name.to_vec() };
        assert!(watcher.relevant(&[event(wd, libc::IN_MOVED_TO, b"bridge.conf")]).unwrap());
        assert!(!watcher.relevant(&[event(wd, libc::IN_MOVED_TO, b"bridge.conf.lock")]).unwrap());
        assert!(!watcher.relevant(&[event(wd + 1, libc::IN_MOVED_TO, b"bridge.conf")]).unwrap());
        assert!(watcher.relevant(&[event(-1, libc::IN_Q_OVERFLOW, b"")]).unwrap());
        assert!(watcher.relevant(&[event(wd, libc::IN_MOVE_SELF, b"")]).unwrap());
        assert!(watcher.relevant(&[event(watcher.wd, libc::IN_IGNORED, b"")]).unwrap());
        assert!(!watcher.relevant(&[]).unwrap());
        // A file as the folder: cannot be watched again.
        let parent = dir.join("p");
        let mut lost = ConsentWatcher::new(&parent.join("bridge.conf")).unwrap();
        std::fs::remove_dir(&parent).unwrap();
        std::fs::write(&parent, b"").unwrap();
        lost.relevant(&[event(lost.wd, libc::IN_IGNORED, b"")]).unwrap_err();
        // A bare file name: its folder is the current one.
        assert_eq!(ConsentWatcher::new(Path::new("bridge.conf")).unwrap().folder, Path::new("."));
    }
}
