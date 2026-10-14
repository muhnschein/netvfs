// SPDX-License-Identifier: LGPL-2.1-or-later
//! `accounts.db` of libaccounts-glib, read and written with SQLite directly.
//!
//! Tables (`create_db`, ag-manager.c): `Accounts(id, name, provider,
//! enabled)`, `Services(id, name, display, provider, type)` and
//! `Settings(account, service, key, type, value)`, where service 0 is the
//! account's global settings and a service's `enabled` flag is its setting
//! `enabled`. Keys are bytes: libaccounts-qt converts them to and from
//! Latin-1.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::gvariant;
use crate::qvariant::{QString, Value, cut_to_int};

/// Where libaccounts-glib keeps the database below the data folder on
/// Sailfish OS (its spec: `-Ddatabase-dir=system/privileged/Accounts/libaccounts-glib`).
pub const SAILFISH_DATABASE_DIR: &str = "system/privileged/Accounts/libaccounts-glib";
/// The folder whose owner and mode libaccounts-glib checks on Sailfish OS
/// (`-Dprivileged-dir=system/privileged`).
pub const SAILFISH_PRIVILEGED_DIR: &str = "system/privileged";
/// The upstream location, below the configuration folder.
pub const UPSTREAM_DATABASE_DIR: &str = "libaccounts-glib";
/// The database file in its folder.
pub const DATABASE_FILE: &str = "accounts.db";
const REDIRECT_FILE: &str = "accounts.redirect";
/// How long a read or write waits for another writer.
const BUSY_TIMEOUT_MS: u64 = 5000;

/// Where to look for the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// A test's: `$ACCOUNTS/accounts.db` (never in a set-id process).
    Explicit(PathBuf),
    /// Sailfish OS: below `data_home`, owned by the group `privileged`.
    Sailfish {
        /// The XDG data folder.
        data_home: PathBuf,
    },
    /// Upstream libaccounts-glib, below `config_home`.
    Upstream {
        /// The XDG configuration folder.
        config_home: PathBuf,
    },
}

/// The environment the location comes from.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    /// The `ACCOUNTS` variable: the database folder, for tests.
    pub accounts: Option<String>,
    /// The `HOME` variable.
    pub home: Option<String>,
    /// The `XDG_DATA_HOME` variable.
    pub xdg_data_home: Option<String>,
    /// The `XDG_CONFIG_HOME` variable.
    pub xdg_config_home: Option<String>,
}

impl Environment {
    /// The environment of this process.
    #[must_use]
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned());
        Self {
            accounts: var("ACCOUNTS"),
            home: var("HOME"),
            xdg_data_home: var("XDG_DATA_HOME"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
        }
    }

    /// An XDG folder: the variable when it is absolute, else `$HOME/<fallback>`.
    fn xdg(&self, value: Option<&String>, fallback: &str) -> PathBuf {
        match value {
            Some(v) if v.starts_with('/') => PathBuf::from(v),
            _ => Path::new(self.home.as_deref().unwrap_or_default()).join(fallback),
        }
    }

    /// The XDG data folder: `XDG_DATA_HOME` when absolute, else `$HOME/.local/share`.
    #[must_use]
    pub fn data_home(&self) -> PathBuf {
        self.xdg(self.xdg_data_home.as_ref(), ".local/share")
    }

    /// The XDG configuration folder: `XDG_CONFIG_HOME` when absolute, else `$HOME/.config`.
    #[must_use]
    pub fn config_home(&self) -> PathBuf {
        self.xdg(self.xdg_config_home.as_ref(), ".config")
    }

    /// The database libaccounts-glib would open: `ACCOUNTS` when set, else
    /// the Sailfish OS folder when its privileged folder exists, else the
    /// upstream one.
    #[must_use]
    pub fn location(&self) -> Location {
        if let Some(dir) = &self.accounts {
            return Location::Explicit(PathBuf::from(dir));
        }
        let data_home = self.data_home();
        if fs::symlink_metadata(data_home.join(SAILFISH_PRIVILEGED_DIR)).is_ok() {
            Location::Sailfish { data_home }
        } else {
            Location::Upstream { config_home: self.config_home() }
        }
    }

    /// The folders the confinement lets the helper write to: `ACCOUNTS`
    /// when set and absolute, else both places a database may be.
    #[must_use]
    pub fn database_folders(&self) -> Vec<PathBuf> {
        if let Some(dir) = self.accounts.as_ref().filter(|d| d.starts_with('/')) {
            return vec![PathBuf::from(dir)];
        }
        vec![
            self.data_home().join("system/privileged/Accounts"),
            self.config_home().join(UPSTREAM_DATABASE_DIR),
        ]
    }
}

/// The database cannot be opened or read: what a helper without the group
/// `privileged` sees on Sailfish OS.
#[derive(Debug)]
pub struct Unusable(pub String);

impl From<rusqlite::Error> for Unusable {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

/// libaccounts-glib's check of the privileged folder on Sailfish OS: owned
/// by user and group `privileged`, nothing for others.
pub trait PrivilegedOwner {
    /// The uid and gid of the user `privileged`, if there is one.
    fn privileged_ids(&self) -> Option<(u32, u32)>;
}

impl Location {
    /// The database file, following an `accounts.redirect` as
    /// libaccounts-glib does (Sailfish OS and upstream locations only).
    ///
    /// # Errors
    /// When the Sailfish OS privileged folder is not as libaccounts-glib
    /// requires.
    pub fn database(&self, owner: &dyn PrivilegedOwner) -> Result<PathBuf, Unusable> {
        let folder = match self {
            Self::Explicit(dir) => return Ok(dir.join(DATABASE_FILE)),
            Self::Sailfish { data_home } => {
                check_privileged_folder(&data_home.join(SAILFISH_PRIVILEGED_DIR), owner)?;
                data_home.join(SAILFISH_DATABASE_DIR)
            }
            Self::Upstream { config_home } => config_home.join(UPSTREAM_DATABASE_DIR),
        };
        let folder = match fs::read(folder.join(REDIRECT_FILE)) {
            Ok(contents) => {
                // g_strstrip, then g_build_path: always below the folder.
                let target = String::from_utf8_lossy(&contents);
                folder.join(target.trim().trim_start_matches('/'))
            }
            Err(_) => folder,
        };
        Ok(folder.join(DATABASE_FILE))
    }
}

fn check_privileged_folder(path: &Path, owner: &dyn PrivilegedOwner) -> Result<(), Unusable> {
    use std::os::unix::fs::MetadataExt;
    let Some((uid, gid)) = owner.privileged_ids() else {
        return Err(Unusable("there is no user privileged".into()));
    };
    let meta = fs::metadata(path).map_err(|e| Unusable(format!("{}: {e}", path.display())))?;
    if meta.uid() != uid || meta.gid() != gid {
        return Err(Unusable(format!("{} is not owned by privileged", path.display())));
    }
    if meta.mode() & 0o007 != 0 {
        return Err(Unusable(format!("{} is open to others", path.display())));
    }
    Ok(())
}

/// An open database, or the empty one libaccounts-glib would create where
/// there is none yet.
#[derive(Debug)]
pub struct Database {
    connection: Option<Connection>,
}

/// One row of `Accounts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    /// The account's id (`Accounts.id`).
    pub id: i64,
    /// The account's name (`Accounts.name`).
    pub display_name: QString,
    /// The account's provider (`Accounts.provider`).
    pub provider: QString,
    /// Whether the account is enabled.
    pub enabled: bool,
}

/// A setting as read: key bytes and value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The key, as stored.
    pub key: Vec<u8>,
    /// The value, as the `QVariant` it reads as.
    pub value: Value,
}

/// A setting to write: key, `GVariant` type and printed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSetting {
    /// The key, as stored.
    pub key: Vec<u8>,
    /// The `GVariant` type string.
    pub type_string: &'static str,
    /// The value, printed as `g_variant_print()` writes it.
    pub text: String,
}

fn text(v: ValueRef<'_>) -> QString {
    match v {
        ValueRef::Text(t) | ValueRef::Blob(t) => Some(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(r) => Some(r.to_string()),
        ValueRef::Null => None,
    }
}

fn bytes(v: ValueRef<'_>) -> Option<Vec<u8>> {
    match v {
        ValueRef::Text(t) | ValueRef::Blob(t) => Some(t.to_vec()),
        ValueRef::Integer(i) => Some(i.to_string().into_bytes()),
        ValueRef::Real(r) => Some(r.to_string().into_bytes()),
        ValueRef::Null => None,
    }
}

impl Database {
    /// Opens `path`; read-only unless `writable`. A missing file is the
    /// empty database, which is not created.
    ///
    /// # Errors
    /// When the file or its folder cannot be reached, or SQLite cannot open it.
    pub fn open(path: &Path, writable: bool) -> Result<Self, Unusable> {
        match fs::metadata(path) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self { connection: None }),
            Err(e) => return Err(Unusable(format!("{}: {e}", path.display()))),
        }
        let mode =
            if writable { OpenFlags::SQLITE_OPEN_READ_WRITE } else { OpenFlags::SQLITE_OPEN_READ_ONLY };
        let connection = Connection::open_with_flags(path, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        connection.busy_timeout(std::time::Duration::from_millis(BUSY_TIMEOUT_MS))?;
        // Version 0: no tables yet, which libaccounts-glib would create.
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(Self { connection: (version >= 1).then_some(connection) })
    }

    /// The empty database.
    #[must_use]
    pub fn empty() -> Self {
        Self { connection: None }
    }

    /// `ag_manager_list_by_service_type`: accounts of a provider that has a
    /// service of `service_type`.
    ///
    /// # Errors
    /// When SQLite fails.
    pub fn accounts_with_service_type(&self, service_type: &str) -> Result<Vec<i64>, Unusable> {
        let Some(c) = &self.connection else { return Ok(Vec::new()) };
        let mut statement = c.prepare(
            "SELECT id FROM Accounts WHERE provider IN (SELECT provider FROM Services WHERE type = ?1)",
        )?;
        let ids = statement.query_map([service_type], |row| row.get::<_, i64>(0))?;
        Ok(ids.collect::<Result<_, _>>()?)
    }

    /// The account `id`, if it exists.
    ///
    /// # Errors
    /// When SQLite fails.
    pub fn account(&self, id: i64) -> Result<Option<AccountRow>, Unusable> {
        let Some(c) = &self.connection else { return Ok(None) };
        Ok(c.query_row(
            "SELECT name, provider, CAST(enabled AS INTEGER) FROM Accounts WHERE id = ?1",
            [id],
            |row| {
                Ok(AccountRow {
                    id,
                    display_name: text(row.get_ref(0)?),
                    provider: text(row.get_ref(1)?),
                    // sqlite3_column_int, as a gboolean
                    enabled: row.get::<_, Option<i64>>(2)?.is_some_and(|v| cut_to_int(v) != 0),
                })
            },
        )
        .optional()?)
    }

    /// The id of the service named `name` in `Services`. A service missing
    /// there has no settings.
    ///
    /// # Errors
    /// When SQLite fails.
    pub fn service_id(&self, name: &str) -> Result<Option<i64>, Unusable> {
        let Some(c) = &self.connection else { return Ok(None) };
        Ok(c.query_row("SELECT id FROM Services WHERE name = ?1", [name], |row| row.get(0)).optional()?)
    }

    /// The settings of `account` for `service` (0: global).
    ///
    /// # Errors
    /// When SQLite fails.
    pub fn settings(&self, account: i64, service: i64) -> Result<Vec<Setting>, Unusable> {
        let Some(c) = &self.connection else { return Ok(Vec::new()) };
        let mut statement =
            c.prepare("SELECT key, type, value FROM Settings WHERE account = ?1 AND service = ?2")?;
        let rows = statement.query_map(params![account, service], |row| {
            let key = bytes(row.get_ref(0)?).unwrap_or_default();
            let type_string = bytes(row.get_ref(1)?).unwrap_or_default();
            let value = gvariant::from_db(&type_string, bytes(row.get_ref(2)?).as_deref());
            Ok(Setting { key, value })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Writes global settings of `account` in one exclusive transaction, as
    /// `ag_account_store` does.
    ///
    /// # Errors
    /// When there is no database or SQLite fails.
    pub fn store_global(&mut self, account: i64, settings: &[NewSetting]) -> Result<(), Unusable> {
        let Some(c) = &mut self.connection else { return Err(Unusable("no accounts database".into())) };
        let transaction = c.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        for s in settings {
            transaction.execute(
                "INSERT OR REPLACE INTO Settings (account, service, key, type, value) VALUES (?1, 0, ?2, ?3, ?4)",
                params![account, s.key, s.type_string, s.text],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

/// The tables as libaccounts-glib's `create_db` makes them, for tests.
#[cfg(test)]
pub(crate) const TEST_SCHEMA: &str =
    "CREATE TABLE Accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, provider TEXT, enabled INTEGER);
     CREATE TABLE Services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                            display TEXT NOT NULL, provider TEXT, type TEXT);
     CREATE TABLE Settings (account INTEGER NOT NULL, service INTEGER, key TEXT NOT NULL,
                            type TEXT NOT NULL, value BLOB);
     CREATE UNIQUE INDEX idx_setting ON Settings (account, service, key);
     PRAGMA user_version = 1;";

#[cfg(test)]
mod tests {
    use super::*;

    struct Owner(Option<(u32, u32)>);
    impl PrivilegedOwner for Owner {
        fn privileged_ids(&self) -> Option<(u32, u32)> {
            self.0
        }
    }

    fn env(home: &str) -> Environment {
        Environment { home: Some(home.into()), ..Environment::default() }
    }

    #[test]
    fn locations() {
        let e = Environment { accounts: Some("/fixture".into()), ..env("/home/a") };
        assert_eq!(e.location(), Location::Explicit("/fixture".into()));
        assert_eq!(e.database_folders(), vec![PathBuf::from("/fixture")]);
        // A relative ACCOUNTS is libaccounts' too, but gets no folder.
        let relative = Environment { accounts: Some("rel".into()), ..env("/home/a") };
        assert_eq!(relative.location(), Location::Explicit("rel".into()));
        let e = Environment { xdg_config_home: Some("relative".into()), ..env("/nonexistent/home") };
        assert_eq!(e.location(), Location::Upstream { config_home: "/nonexistent/home/.config".into() });
        assert_eq!(
            e.database_folders(),
            vec![
                PathBuf::from("/nonexistent/home/.local/share/system/privileged/Accounts"),
                PathBuf::from("/nonexistent/home/.config/libaccounts-glib")
            ]
        );
        let e = Environment {
            xdg_data_home: Some("/data".into()),
            xdg_config_home: Some("/config".into()),
            ..env("/h")
        };
        assert_eq!(e.data_home(), PathBuf::from("/data"));
        assert_eq!(e.config_home(), PathBuf::from("/config"));
    }

    #[test]
    fn sailfish_location_and_redirect() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempdir();
        let privileged = dir.join(".local/share/system/privileged");
        let db_dir = dir.join(".local/share").join(SAILFISH_DATABASE_DIR);
        fs::create_dir_all(&db_dir).unwrap_or_default();
        let e = env(dir.to_str().unwrap_or_default());
        let location = e.location();
        assert_eq!(location, Location::Sailfish { data_home: dir.join(".local/share") });
        let meta = fs::metadata(&privileged).ok();
        let ids = meta.as_ref().map(|m| (m.uid(), m.gid()));
        fs::set_permissions(&privileged, fs::Permissions::from_mode(0o770)).unwrap_or_default();
        assert_eq!(location.database(&Owner(ids)).ok(), Some(db_dir.join(DATABASE_FILE)));
        location.database(&Owner(None)).unwrap_err();
        location.database(&Owner(ids.map(|(u, g)| (u + 1, g)))).unwrap_err();
        location.database(&Owner(ids.map(|(u, g)| (u, g + 1)))).unwrap_err();
        fs::set_permissions(&privileged, fs::Permissions::from_mode(0o771)).unwrap_or_default();
        location.database(&Owner(ids)).unwrap_err();
        fs::set_permissions(&privileged, fs::Permissions::from_mode(0o770)).unwrap_or_default();
        fs::write(db_dir.join(REDIRECT_FILE), " /moved \n").unwrap_or_default();
        assert_eq!(location.database(&Owner(ids)).ok(), Some(db_dir.join("moved").join(DATABASE_FILE)));
        let upstream = Location::Upstream { config_home: dir.join("cfg") };
        assert_eq!(upstream.database(&Owner(None)).ok(), Some(dir.join("cfg/libaccounts-glib/accounts.db")));
        fs::remove_dir_all(dir).ok();
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netvfs-accounts-db-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap_or_default();
        dir
    }

    fn create(path: &Path) -> Connection {
        let c = Connection::open(path).or_else(|_| Connection::open_in_memory()).unwrap();
        c.execute_batch(TEST_SCHEMA).unwrap_or_default();
        c.execute_batch(
            "INSERT INTO Accounts VALUES (1, 'alice@nas', 'smb', 1), (2, NULL, 'smb', 0), (3, 'x', 'other', 1);
             INSERT INTO Services VALUES (1, 'smb-files', 'Files', 'smb', 'netvfs-files');
             INSERT INTO Settings VALUES (1, 0, 'netvfs/host', 's', '''nas''');
             INSERT INTO Settings VALUES (1, 1, 'enabled', 'b', 'true');",
        )
        .unwrap_or_default();
        c
    }

    #[test]
    fn reads_and_writes() {
        let dir = tempdir();
        let path = dir.join(DATABASE_FILE);
        let missing = Database::open(&path, false).ok();
        assert!(missing.as_ref().is_some_and(|d| d.connection.is_none()));
        let missing = missing.unwrap_or_else(Database::empty);
        assert_eq!(missing.accounts_with_service_type("netvfs-files").ok(), Some(vec![]));
        assert_eq!(missing.account(1).ok(), Some(None));
        assert_eq!(missing.service_id("smb-files").ok(), Some(None));
        assert_eq!(missing.settings(1, 0).ok(), Some(vec![]));
        assert!(Database::empty().store_global(1, &[]).is_err());

        drop(create(&path));
        let db = Database::open(&path, false).unwrap_or_else(|_| Database::empty());
        let mut ids = db.accounts_with_service_type("netvfs-files").unwrap_or_default();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
        assert_eq!(
            db.account(1).ok().flatten(),
            Some(AccountRow {
                id: 1,
                display_name: Some("alice@nas".into()),
                provider: Some("smb".into()),
                enabled: true
            })
        );
        assert_eq!(db.account(2).ok().flatten().map(|a| (a.display_name, a.enabled)), Some((None, false)));
        assert_eq!(db.account(9).ok(), Some(None));
        assert_eq!(db.service_id("smb-files").ok(), Some(Some(1)));
        assert_eq!(
            db.settings(1, 0).ok(),
            Some(vec![Setting { key: b"netvfs/host".to_vec(), value: Value::String("nas".into()) }])
        );
        // Read-only: a write fails.
        let mut db = db;
        let new =
            NewSetting { key: b"netvfs/attention".to_vec(), type_string: "s", text: "'auth-failed'".into() };
        assert!(db.store_global(1, std::slice::from_ref(&new)).is_err());

        let mut db = Database::open(&path, true).unwrap_or_else(|_| Database::empty());
        assert!(matches!(db.store_global(1, &[new.clone(), new]), Ok(())));
        let settings = db.settings(1, 0).unwrap_or_default();
        assert_eq!(settings.len(), 2);
        assert!(settings.contains(&Setting {
            key: b"netvfs/attention".to_vec(),
            value: Value::String("auth-failed".into())
        }));

        // No tables yet: empty.
        let blank = dir.join("blank.db");
        drop(Connection::open(&blank));
        let db = Database::open(&blank, false).unwrap_or_else(|_| Database::empty());
        assert!(db.connection.is_none());
        // Not a database: unusable.
        let junk = dir.join("junk.db");
        fs::write(&junk, vec![b'x'; 4096]).unwrap_or_default();
        Database::open(&junk, false).unwrap_err();
        // A folder that is a file: unusable.
        Database::open(&junk.join(DATABASE_FILE), false).unwrap_err();
        fs::remove_dir_all(dir).ok();
    }
}
