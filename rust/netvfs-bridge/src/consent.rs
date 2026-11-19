// SPDX-License-Identifier: LGPL-2.1-or-later
//! User's choices per consumer in `~/.config/netvfs/bridge.conf`, a `QSettings` INI file the account UI writes: `[Consent] <id>=ask|<level>|denied` once decided (what accounts without a choice of their own get), `[Access] <id>\<accountId>=<level>|denied` per account. Levels: `full`, `read-add`, `read`, `add`.
//!
//! [`ConsentStore`] reads the file on every call; a write (tests; the bridge never writes) takes the `QLockFile`-compatible `bridge.conf.lock` as `QSettings` does, edits in place (other groups and keys stay) and replaces atomically. Both block: run on the blocking pool. [`ConsentWatcher`] reports changes through inotify on the folder (writers replace the file).

use crate::config::is_valid_id;
use crate::ini::IniFile;
use crate::lockfile::LockFile;
use crate::savefile::{self, Mode};
use crate::sys::inotify::{Event, Inotify};
pub use netvfs_bridge_proto::access::Level;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// The `[Consent]` group: `<id>=<word>`, the app has decided; the word is for accounts without their own entry.
const GROUP: &str = "Consent";
/// The `[Access]` group: `<id>\<accountId>=<level>`, one account's choice.
const ACCESS_GROUP: &str = "Access";
/// How long a write waits for another writer's lock. `QSettings` waits forever; the bridge gives up and fails the write.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// `denied`: the stored word for "not allowed".
pub const DENIED: &str = "denied";
/// `ask`: new accounts wait for the user.
pub const ASK: &str = "ask";

/// One account's choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Allowed at this level.
    Allow(Level),
    /// `denied`: not allowed.
    Deny,
}

impl Choice {
    /// The stored word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow(level) => level.as_str(),
            Self::Deny => DENIED,
        }
    }

    /// The choice of a word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        if word == DENIED { Some(Self::Deny) } else { Level::parse(word).map(Self::Allow) }
    }
}

/// What accounts without their own choice get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewAccounts {
    /// `ask`: the user is asked again.
    Ask,
    /// This choice.
    Set(Choice),
}

impl NewAccounts {
    /// The stored word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ask => ASK,
            Self::Set(choice) => choice.as_str(),
        }
    }

    /// The value of a word; `granted` and `denied` from before levels existed set every account.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            ASK => Some(Self::Ask),
            "granted" => Some(Self::Set(Choice::Allow(Level::Full))),
            _ => Choice::parse(word).map(Self::Set),
        }
    }
}

/// One account for one app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// Allowed at this level.
    Allowed(Level),
    /// Not allowed.
    Denied,
    /// The user has not chosen yet.
    Undecided,
}

/// A consumer's stored choices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Consent {
    /// `None`: never decided (no `[Consent]` entry).
    pub new_accounts: Option<NewAccounts>,
    /// The accounts with a choice of their own.
    pub accounts: BTreeMap<i32, Choice>,
}

impl Consent {
    /// Never decided.
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Decided: every account `choice`.
    #[must_use]
    pub fn all(choice: Choice) -> Self {
        Self { new_accounts: Some(NewAccounts::Set(choice)), accounts: BTreeMap::new() }
    }

    /// Whether the user has decided at all.
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        self.new_accounts.is_some()
    }

    /// `GetConsent` and `ConsentChanged`: `decided` or `unknown`.
    #[must_use]
    pub const fn wire(&self) -> &'static str {
        if self.is_decided() { "decided" } else { "unknown" }
    }

    /// The account `account_id`.
    #[must_use]
    pub fn grant(&self, account_id: i32) -> Grant {
        let Some(new_accounts) = self.new_accounts else { return Grant::Undecided };
        match (self.accounts.get(&account_id).copied(), new_accounts) {
            (Some(Choice::Allow(level)), _) | (None, NewAccounts::Set(Choice::Allow(level))) => {
                Grant::Allowed(level)
            }
            (Some(Choice::Deny), _) | (None, NewAccounts::Set(Choice::Deny)) => Grant::Denied,
            (None, NewAccounts::Ask) => Grant::Undecided,
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

    /// Choices of consumer `id`, read now; unknown for an invalid id or unreadable file. Unknown words are skipped.
    #[must_use]
    pub fn consent(&self, id: &str) -> Consent {
        if !is_valid_id(id) {
            return Consent::unknown();
        }
        let file = IniFile::parse(std::fs::read(&self.path).unwrap_or_default());
        let new_accounts = NewAccounts::parse(&file.string(&format!("{GROUP}/{id}")));
        let prefix: Vec<u16> = format!("{ACCESS_GROUP}/{id}/").encode_utf16().collect();
        let accounts = file
            .keys()
            .filter_map(|key| key.strip_prefix(prefix.as_slice()))
            .filter_map(|rest| {
                let account = String::from_utf16(rest).ok()?;
                let account_id =
                    account.parse::<i32>().ok().filter(|n| *n > 0 && account == n.to_string())?;
                let choice = Choice::parse(&file.string(&format!("{ACCESS_GROUP}/{id}/{account}")))?;
                Some((account_id, choice))
            })
            .collect();
        Consent { new_accounts, accounts }
    }

    /// Stores the choices of consumer `id`, as the account UI does: unknown removes them. No-op for an invalid id. Failures are logged too.
    ///
    /// # Errors
    /// Folder or file not writable, or another writer holds the lock for [`LOCK_TIMEOUT`].
    pub fn set_consent(&self, id: &str, consent: &Consent) -> io::Result<()> {
        if !is_valid_id(id) {
            return Ok(());
        }
        let written = self.write(id, consent);
        if let Err(e) = &written {
            crate::log::warning(format_args!("Cannot store the consent of {id}: {e}"));
        }
        written
    }

    fn write(&self, id: &str, consent: &Consent) -> io::Result<()> {
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
        let prefix: Vec<u16> = format!("{ACCESS_GROUP}/{id}/").encode_utf16().collect();
        let stale: Vec<String> = file
            .keys()
            .filter_map(|key| key.strip_prefix(prefix.as_slice()))
            .map(String::from_utf16_lossy)
            .collect();
        for account in stale {
            file.remove(ACCESS_GROUP, &format!("{id}/{account}"));
        }
        match consent.new_accounts {
            None => file.remove(GROUP, id),
            Some(new_accounts) => {
                for (account, choice) in &consent.accounts {
                    file.set_string(ACCESS_GROUP, &format!("{id}/{account}"), choice.as_str());
                }
                file.set_string(GROUP, id, new_accounts.as_str());
            }
        }
        savefile::save(&self.path, file.as_bytes(), Mode::KeepOrDefault)
    }
}

/// Watcher reacts to these in the folder. A removed folder needs no flag: its watch ends with `IN_IGNORED`.
const FOLDER_EVENTS: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR;

/// Reports changes of the consent file. Watches the folder so a file replaced by rename is seen; a removed folder is created and watched again.
#[derive(Debug)]
pub struct ConsentWatcher {
    inotify: AsyncFd<Inotify>,
    folder: PathBuf,
    name: Vec<u8>,
    wd: i32,
}

impl ConsentWatcher {
    /// Watches the folder of `file`, creating it. Needs a tokio runtime with I/O enabled.
    ///
    /// # Errors
    /// Folder cannot be created or watched.
    pub fn new(file: &Path) -> io::Result<Self> {
        let folder =
            file.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new(".")).to_owned();
        let name = file.file_name().map(|n| n.as_bytes().to_vec()).unwrap_or_default();
        let inotify = Inotify::new()?;
        let wd = watch(&inotify, &folder)?;
        Ok(Self { inotify: inotify.register()?, folder, name, wd })
    }

    /// Waits until the file may have changed (written, replaced, removed, or its folder). Several changes at once are one.
    ///
    /// # Errors
    /// inotify fails, or the folder cannot be watched again.
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

    fn relevant(&mut self, events: &[Event]) -> io::Result<bool> {
        let mut changed = false;
        for event in events {
            if event.mask & libc::IN_Q_OVERFLOW != 0 {
                changed = true;
            } else if event.wd != self.wd {
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

    const fn allow(level: Level) -> Choice {
        Choice::Allow(level)
    }

    #[test]
    fn new_account_words() {
        for (word, value) in [
            ("ask", NewAccounts::Ask),
            ("denied", NewAccounts::Set(Choice::Deny)),
            ("full", NewAccounts::Set(allow(Level::Full))),
            ("read-add", NewAccounts::Set(allow(Level::ReadAdd))),
            ("read", NewAccounts::Set(allow(Level::Read))),
            ("add", NewAccounts::Set(allow(Level::Add))),
        ] {
            assert_eq!(NewAccounts::parse(word), Some(value));
            assert_eq!(value.as_str(), word);
        }
        assert_eq!(NewAccounts::parse("granted"), Some(NewAccounts::Set(allow(Level::Full))));
        assert_eq!(NewAccounts::parse("unknown"), None);
        assert_eq!(NewAccounts::parse(""), None);
    }

    #[test]
    fn grants() {
        assert_eq!(Consent::unknown().grant(1), Grant::Undecided);
        assert!(!Consent::unknown().is_decided());
        assert_eq!(Consent::unknown().wire(), "unknown");
        let mut c = Consent::all(allow(Level::Read));
        assert!(c.is_decided());
        assert_eq!(c.wire(), "decided");
        assert_eq!(c.grant(1), Grant::Allowed(Level::Read));
        c.accounts.insert(2, Choice::Deny);
        c.accounts.insert(3, allow(Level::Add));
        assert_eq!(c.grant(2), Grant::Denied);
        assert_eq!(c.grant(3), Grant::Allowed(Level::Add));
        assert_eq!(c.grant(4), Grant::Allowed(Level::Read));
        c.new_accounts = Some(NewAccounts::Ask);
        assert_eq!(c.grant(4), Grant::Undecided);
        assert_eq!(c.grant(3), Grant::Allowed(Level::Add));
        c.new_accounts = Some(NewAccounts::Set(Choice::Deny));
        assert_eq!(c.grant(4), Grant::Denied);
        c.new_accounts = None;
        assert_eq!(c.grant(3), Grant::Undecided);
        assert_eq!(Consent::all(Choice::Deny).grant(9), Grant::Denied);
    }

    #[test]
    fn consent_round_trip() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("sub/bridge.conf"));
        assert_eq!(store.consent("lautta"), Consent::unknown());
        let full = Consent::all(allow(Level::Full));
        store.set_consent("lautta", &full).unwrap();
        assert_eq!(ConsentStore::new(store.path()).consent("lautta"), full);
        assert_eq!(store.consent("other"), Consent::unknown());
        let mut mixed = Consent { new_accounts: Some(NewAccounts::Ask), accounts: BTreeMap::new() };
        mixed.accounts.insert(1, allow(Level::ReadAdd));
        mixed.accounts.insert(12, Choice::Deny);
        store.set_consent("lautta", &mixed).unwrap();
        assert_eq!(store.consent("lautta"), mixed);
        let mut fewer = Consent::all(Choice::Deny);
        fewer.accounts.insert(3, allow(Level::Add));
        store.set_consent("lautta", &fewer).unwrap();
        assert_eq!(store.consent("lautta"), fewer);
        store.set_consent("lautta", &Consent::unknown()).unwrap();
        assert_eq!(store.consent("lautta"), Consent::unknown());
        assert_eq!(std::fs::read(store.path()).unwrap(), b"[Consent]\n\n[Access]\n");
        store.set_consent("Bad", &full).unwrap();
        assert_eq!(std::fs::read(store.path()).unwrap(), b"[Consent]\n\n[Access]\n");
        assert!(!dir.join("sub/bridge.conf.lock").exists());
        std::fs::write(store.path(), "[Consent]\nBad=full\n").unwrap();
        assert_eq!(store.consent("Bad"), Consent::unknown());
    }

    /// Unknown words, account ids that are not plain positive numbers and other apps' entries are skipped.
    #[test]
    fn odd_entries() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("bridge.conf"));
        std::fs::write(
            store.path(),
            "[Consent]\nlautta=granted\nother=maybe\n\n[Access]\nlautta\\1=read\nlautta\\2=maybe\nlautta\\02=add\nlautta\\0=add\nlautta\\-3=add\nlautta\\x=add\nlautta\\4\\5=add\nlautta-x\\6=add\nother\\7=full\n",
        )
        .unwrap();
        let mut want = Consent::all(allow(Level::Full));
        want.accounts.insert(1, allow(Level::Read));
        assert_eq!(store.consent("lautta"), want);
        let other = store.consent("other");
        assert!(!other.is_decided());
        assert_eq!(other.accounts.get(&7), Some(&allow(Level::Full)));
        std::fs::write(store.path(), "[Consent]\nlautta=denied\n").unwrap();
        assert_eq!(store.consent("lautta"), Consent::all(Choice::Deny));
    }

    /// A file QSettings wrote (other groups, escapes, lists, types): edits keep every other line; Qt reads the result like its own edit of the same file (generate.sh checks).
    #[test]
    fn keeps_other_groups_and_qt_format() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("bridge.conf"));
        std::fs::write(store.path(), BRIDGE_QT).unwrap();
        assert_eq!(store.consent("lautta"), Consent::all(allow(Level::Full)));
        let mut photos = Consent::all(Choice::Deny);
        photos.accounts.insert(3, allow(Level::Read));
        assert_eq!(store.consent("photos"), photos);
        let mut lautta = Consent { new_accounts: Some(NewAccounts::Ask), accounts: BTreeMap::new() };
        lautta.accounts.insert(1, allow(Level::Read));
        lautta.accounts.insert(2, Choice::Deny);
        store.set_consent("lautta", &lautta).unwrap();
        store.set_consent("photos", &Consent::unknown()).unwrap();
        store.set_consent("new-one", &Consent::all(allow(Level::Full))).unwrap();
        let written = std::fs::read(store.path()).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), String::from_utf8_lossy(BRIDGE_RUST_EDITED));
        assert_eq!(dump(&IniFile::parse(written)), qt_dump(BRIDGE_QT_EDITED_DUMP));
    }

    #[test]
    fn first_write_as_qsettings() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("netvfs/bridge.conf"));
        let mut lautta = Consent { new_accounts: Some(NewAccounts::Ask), accounts: BTreeMap::new() };
        lautta.accounts.insert(1, allow(Level::ReadAdd));
        store.set_consent("lautta", &lautta).unwrap();
        assert_eq!(std::fs::read(store.path()).unwrap(), FRESH);
    }

    #[test]
    fn writes_wait_for_the_lock() {
        let dir = TempDir::new();
        let store = ConsentStore::new(dir.join("bridge.conf"));
        let held = LockFile::try_lock(&dir.join("bridge.conf.lock")).unwrap().unwrap();
        let writer = {
            let store = store.clone();
            std::thread::spawn(move || store.set_consent("lautta", &Consent::all(allow(Level::Full))))
        };
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(store.consent("lautta"), Consent::unknown());
        drop(held);
        writer.join().unwrap().unwrap();
        assert_eq!(store.consent("lautta"), Consent::all(allow(Level::Full)));
        assert_eq!(LOCK_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn unreadable_files_are_kept() {
        let dir = TempDir::new();
        let path = dir.join("bridge.conf");
        std::os::unix::fs::symlink("bridge.conf", &path).unwrap();
        let store = ConsentStore::new(&path);
        let full = Consent::all(allow(Level::Full));
        assert_eq!(store.set_consent("x", &full).unwrap_err().raw_os_error(), Some(libc::ELOOP));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn failures() {
        let dir = TempDir::new();
        let full = Consent::all(allow(Level::Full));
        std::fs::write(dir.join("f"), b"").unwrap();
        ConsentStore::new(dir.join("f/bridge.conf")).set_consent("x", &full).unwrap_err();
        std::fs::create_dir(dir.join("d")).unwrap();
        let store = ConsentStore::new(dir.join("d"));
        assert_eq!(store.consent("x"), Consent::unknown());
        store.set_consent("x", &full).unwrap_err();
    }

    #[tokio::test]
    async fn watcher_sees_writes_replacements_and_removals() {
        let dir = TempDir::new();
        let file = dir.join("netvfs/bridge.conf");
        let mut watcher = ConsentWatcher::new(&file).unwrap();
        assert!(dir.join("netvfs").is_dir());
        let store = ConsentStore::new(&file);
        store.set_consent("lautta", &Consent::all(allow(Level::Full))).unwrap();
        expect_change(&mut watcher).await;
        std::fs::write(&file, b"[Consent]\nlautta=denied\n").unwrap();
        expect_change(&mut watcher).await;
        std::fs::write(dir.join("netvfs/other"), b"x").unwrap();
        expect_quiet(&mut watcher).await;
        std::fs::remove_file(&file).unwrap();
        expect_change(&mut watcher).await;
        std::fs::remove_dir_all(dir.join("netvfs")).unwrap();
        expect_change(&mut watcher).await;
        assert!(dir.join("netvfs").is_dir());
        store.set_consent("lautta", &Consent::all(allow(Level::Full))).unwrap();
        expect_change(&mut watcher).await;
    }

    #[tokio::test]
    async fn every_kind_of_change_is_seen() {
        let dir = TempDir::new();
        let file = dir.join("f/bridge.conf");
        dir.write("f/bridge.conf", "[Consent]\n");
        let mut watcher = ConsentWatcher::new(&file).unwrap();
        std::fs::OpenOptions::new().write(true).truncate(true).open(&file).unwrap();
        expect_change(&mut watcher).await;
        std::fs::rename(&file, dir.join("f/away")).unwrap();
        expect_change(&mut watcher).await;
        std::fs::rename(dir.join("f/away"), &file).unwrap();
        expect_change(&mut watcher).await;
        std::fs::remove_file(&file).unwrap();
        expect_change(&mut watcher).await;
        std::os::unix::fs::symlink("elsewhere", &file).unwrap();
        expect_change(&mut watcher).await;
        std::fs::rename(dir.join("f"), dir.join("g")).unwrap();
        expect_change(&mut watcher).await;
        assert!(dir.join("f").is_dir());
        std::fs::write(&file, b"").unwrap();
        expect_change(&mut watcher).await;
        std::fs::remove_file(dir.join("g/bridge.conf")).unwrap();
        expect_quiet(&mut watcher).await;
    }

    async fn expect_change(watcher: &mut ConsentWatcher) {
        tokio::time::timeout(Duration::from_secs(5), watcher.changed()).await.unwrap().unwrap();
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
        let parent = dir.join("p");
        let mut lost = ConsentWatcher::new(&parent.join("bridge.conf")).unwrap();
        std::fs::remove_dir(&parent).unwrap();
        std::fs::write(&parent, b"").unwrap();
        lost.relevant(&[event(lost.wd, libc::IN_IGNORED, b"")]).unwrap_err();
        assert_eq!(ConsentWatcher::new(Path::new("bridge.conf")).unwrap().folder, Path::new("."));
    }
}
