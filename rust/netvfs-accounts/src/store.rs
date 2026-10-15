// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Files slice of `AccountStore` (src/core/accountstore.cpp) over the
//! database, with what libaccounts-qt does in between: setting keys as
//! Latin-1, values as `QVariant`s.

use crate::db::{Database, NewSetting, Setting, Unusable};
use crate::gvariant;
use crate::policy::ConnectionParams;
use crate::qvariant::{QString, Value, cut_to_int, trimmed};
use crate::wire::{Error, Outcome};

/// The setting keys the helper reads and writes.
pub mod keys {
    /// The server host.
    pub const HOST: &str = "netvfs/host";
    /// The server port.
    pub const PORT: &str = "netvfs/port";
    /// The user name.
    pub const USERNAME: &str = "netvfs/username";
    /// The attention state: `auth-failed` or `server-identity-changed`.
    pub const ATTENTION: &str = "netvfs/attention";
    /// The root folder of the Files service.
    pub const FILES_ROOT: &str = "files_root";
    /// The credentials id.
    pub const CREDENTIALS_ID: &str = "CredentialsId";
    /// Whether the credentials need an update.
    pub const CREDENTIALS_NEED_UPDATE: &str = "CredentialsNeedUpdate";
    /// The service that asked for the update.
    pub const CREDENTIALS_NEED_UPDATE_FROM: &str = "CredentialsNeedUpdateFrom";
    /// The pinned host key, below the provider's `netvfs/<provider>/` prefix.
    pub const HOST_KEY_SEEN: &str = "host_key_seen";
    /// A service's enabled flag.
    pub const ENABLED: &str = "enabled";
}

/// The service type of the Files services (SPEC-v2 XA-1).
pub const FILES_SERVICE_TYPE: &str = "netvfs-files";

/// `Attention` (src/core/accountstore.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attention {
    /// No attention.
    None = 0,
    /// Authentication failed.
    AuthFailed = 1,
    /// The server's host key changed.
    ServerIdentityChanged = 2,
}

impl Attention {
    /// The state `value` names; anything unknown is `None`.
    #[must_use]
    pub fn from_qstring(value: Option<&str>) -> Self {
        match value {
            Some("auth-failed") => Self::AuthFailed,
            Some("server-identity-changed") => Self::ServerIdentityChanged,
            _ => Self::None,
        }
    }

    /// The name the setting stores.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::AuthFailed => "auth-failed",
            Self::ServerIdentityChanged => "server-identity-changed",
        }
    }
}

/// What `AccountStore::load(id, Service::Files)` reads, as far as the
/// helper answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountConfig {
    /// The account's id.
    pub account_id: i32,
    /// The account's provider.
    pub provider: QString,
    /// The account's name.
    pub display_name: QString,
    /// The connection parameters.
    pub params: ConnectionParams,
    /// `files_root` of the Files service, trimmed.
    pub files_root: QString,
    /// The credentials id, as unsigned.
    pub credentials_id: u32,
    /// The attention state.
    pub attention: Attention,
}

/// `QString::fromLatin1`: how libaccounts-qt lists keys.
#[must_use]
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// `QString::toLatin1`: how libaccounts-qt names a key to libaccounts-glib;
/// characters beyond Latin-1 become `?`.
#[must_use]
pub fn to_latin1(s: &str) -> Vec<u8> {
    s.chars().map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?')).collect()
}

fn value_of<'a>(settings: &'a [Setting], key: &str) -> Option<&'a Value> {
    let key = to_latin1(key);
    settings.iter().find(|s| s.key == key).map(|s| &s.value)
}

fn string_of(settings: &[Setting], key: &str) -> QString {
    value_of(settings, key).and_then(Value::to_qstring)
}

/// The providers whose accounts the helper hands out. An account of any
/// other provider (say of a removed backend, still in the database) is not
/// listed.
pub const PROVIDERS: [&str; 2] = ["sftp", "smb"];

/// `serviceName(provider, Service::Files)`.
#[must_use]
pub fn files_service_name(provider: Option<&str>) -> String {
    format!("{}-files", provider.unwrap_or_default())
}

/// The accounts database as `AccountStore` sees it.
#[derive(Debug)]
pub struct Store {
    db: Database,
}

impl Store {
    /// The store over `db`.
    #[must_use]
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// A Files service's settings and whether it is enabled; none when the
    /// service is not in the database.
    fn files_service(&self, account: i64, provider: Option<&str>) -> Result<(Vec<Setting>, bool), Unusable> {
        let Some(service) = self.db.service_id(&files_service_name(provider))? else {
            return Ok((Vec::new(), false));
        };
        let settings = self.db.settings(account, service)?;
        let enabled = matches!(value_of(&settings, keys::ENABLED), Some(Value::Bool(true)));
        Ok((settings, enabled))
    }

    /// `filesAccounts()` (XA-1): enabled accounts of one of [`PROVIDERS`]
    /// whose Files service is enabled, in ascending id order.
    ///
    /// # Errors
    /// When the database cannot be read.
    pub fn files_accounts(&self) -> Result<Vec<i32>, Unusable> {
        let mut ids = Vec::new();
        for id in self.db.accounts_with_service_type(FILES_SERVICE_TYPE)? {
            let Some(account) = self.db.account(id)? else { continue };
            if !account.enabled || !account.provider.as_deref().is_some_and(|p| PROVIDERS.contains(&p)) {
                continue;
            }
            if self.files_service(id, account.provider.as_deref())?.1 {
                // AgAccountId is 32 bits: the id as sqlite3_column_int reads it.
                ids.push(cut_to_int(id));
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// `load(id, Service::Files)`.
    ///
    /// # Errors
    /// The outcome to answer: a missing account, one without a server, or
    /// an unreadable database.
    pub fn load(&self, account_id: i32) -> Result<AccountConfig, Outcome> {
        let unusable = |e: Unusable| unusable_outcome(&e);
        let id = i64::from(u32::from_ne_bytes(account_id.to_ne_bytes()));
        let Some(account) = self.db.account(id).map_err(unusable)? else {
            return Err(Outcome::failure(Error::NotFound, format!("Account {account_id} does not exist")));
        };
        let global = self.db.settings(id, 0).map_err(unusable)?;
        let (files, _) = self.files_service(id, account.provider.as_deref()).map_err(unusable)?;

        let prefix = format!("netvfs/{}/", account.provider.as_deref().unwrap_or_default());
        let options = global
            .iter()
            .filter_map(|s| {
                let key = latin1(&s.key);
                key.strip_prefix(&prefix).map(|k| (k.to_owned(), s.value.clone()))
            })
            .collect();
        let params = ConnectionParams {
            provider: account.provider.clone(),
            host: string_of(&global, keys::HOST),
            port: value_of(&global, keys::PORT).and_then(Value::to_int).unwrap_or(0),
            username: string_of(&global, keys::USERNAME),
            options,
            ..ConnectionParams::default()
        };
        if params.host.as_deref().is_none_or(str::is_empty) {
            return Err(Outcome::failure(Error::Internal, format!("Account {account_id} has no server")));
        }
        // Account::credentialsId(): the value as an int, as unsigned.
        let credentials_id = value_of(&global, keys::CREDENTIALS_ID)
            .and_then(Value::to_int)
            .map_or(0, |v| u32::from_ne_bytes(v.to_ne_bytes()));
        Ok(AccountConfig {
            account_id,
            provider: account.provider,
            display_name: account.display_name,
            params,
            files_root: trimmed(&string_of(&files, keys::FILES_ROOT)),
            credentials_id,
            attention: Attention::from_qstring(string_of(&global, keys::ATTENTION).as_deref()),
        })
    }

    /// `setAttention(id, Service::Files, attention, pin)` (XB-14) for a
    /// loaded account: what it writes, which `write_attention` stores.
    #[must_use]
    pub fn attention_settings(
        config: &AccountConfig,
        attention: Attention,
        pin: Option<&str>,
    ) -> Vec<NewSetting> {
        let string = |key: &str, value: &str| NewSetting {
            key: to_latin1(key),
            type_string: "s",
            text: gvariant::print_string(value),
        };
        let provider = config.provider.as_deref().unwrap_or_default();
        let mut settings = vec![
            string(keys::ATTENTION, attention.as_str()),
            NewSetting {
                key: to_latin1(keys::CREDENTIALS_NEED_UPDATE),
                type_string: "b",
                text: gvariant::print_bool(true).to_owned(),
            },
            string(keys::CREDENTIALS_NEED_UPDATE_FROM, &files_service_name(Some(provider))),
        ];
        if let Some(pin) = pin.filter(|p| !p.is_empty()) {
            settings.push(string(&format!("netvfs/{provider}/{}", keys::HOST_KEY_SEEN), pin));
        }
        settings
    }

    /// Stores `settings` for the account.
    ///
    /// # Errors
    /// `Internal` when the write fails, as `AccountStore` reports it.
    pub fn write_attention(&mut self, account_id: i32, settings: &[NewSetting]) -> Result<(), Outcome> {
        let id = i64::from(u32::from_ne_bytes(account_id.to_ne_bytes()));
        // The SQLite reason stays out of the answer: the bridge shows this message as it is.
        if self.db.store_global(id, settings).is_err() {
            return Err(Outcome::failure(Error::Internal, "Cannot write the accounts database"));
        }
        Ok(())
    }
}

/// What `databaseUsable()` answers for an unreadable database.
#[must_use]
pub fn unusable_outcome(e: &Unusable) -> Outcome {
    Outcome::failure(
        Error::PermissionDenied,
        format!(
            "Cannot open the accounts database ({}). Is netvfs-accounts installed setgid privileged?",
            e.0
        ),
    )
}

/// `Paths::normalize()` (SPEC C-15): `None` for an invalid path. Repeated
/// and trailing separators go, a leading one stays; "." and ".." and NUL are
/// refused. An empty result is the null string, as `QStringList::join` makes it.
#[must_use]
pub fn normalize(path: Option<&str>) -> Option<QString> {
    let path = path.unwrap_or_default();
    if path.contains('\0') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == "." || *p == "..") {
        return None;
    }
    let joined = parts.join("/");
    Some(if path.starts_with('/') {
        Some(format!("/{joined}"))
    } else if joined.is_empty() {
        None
    } else {
        Some(joined)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_names() {
        assert_eq!(Attention::from_qstring(Some("auth-failed")), Attention::AuthFailed);
        assert_eq!(
            Attention::from_qstring(Some("server-identity-changed")),
            Attention::ServerIdentityChanged
        );
        for other in [Some("none"), Some(""), None, Some("Auth-failed")] {
            assert_eq!(Attention::from_qstring(other), Attention::None);
        }
        assert_eq!(Attention::AuthFailed.as_str(), "auth-failed");
        assert_eq!(Attention::ServerIdentityChanged.as_str(), "server-identity-changed");
        assert_eq!(Attention::None.as_str(), "");
    }

    #[test]
    fn latin1_keys() {
        assert_eq!(latin1(b"a\xe4"), "a\u{e4}");
        assert_eq!(to_latin1("a\u{e4}\u{20ac}"), b"a\xe4?");
        assert_eq!(files_service_name(Some("smb")), "smb-files");
        assert_eq!(files_service_name(None), "-files");
    }

    #[test]
    fn paths() {
        assert_eq!(normalize(Some("photos//2026/")), Some(Some("photos/2026".into())));
        assert_eq!(normalize(Some("/a/b")), Some(Some("/a/b".into())));
        assert_eq!(normalize(Some("/")), Some(Some("/".into())));
        assert_eq!(normalize(Some("//")), Some(Some("/".into())));
        assert_eq!(normalize(Some("")), Some(None));
        assert_eq!(normalize(None), Some(None));
        assert_eq!(normalize(Some("a/../b")), None);
        assert_eq!(normalize(Some("./a")), None);
        assert_eq!(normalize(Some("a\0b")), None);
        assert_eq!(normalize(Some("a/.../b")), Some(Some("a/.../b".into())));
    }

    #[test]
    fn attention_writes() {
        let config = AccountConfig {
            account_id: 3,
            provider: Some("sftp".into()),
            display_name: None,
            params: ConnectionParams::default(),
            files_root: None,
            credentials_id: 0,
            attention: Attention::None,
        };
        let without_pin = Store::attention_settings(&config, Attention::AuthFailed, Some(""));
        assert_eq!(
            without_pin,
            vec![
                NewSetting {
                    key: b"netvfs/attention".to_vec(),
                    type_string: "s",
                    text: "'auth-failed'".into()
                },
                NewSetting { key: b"CredentialsNeedUpdate".to_vec(), type_string: "b", text: "true".into() },
                NewSetting {
                    key: b"CredentialsNeedUpdateFrom".to_vec(),
                    type_string: "s",
                    text: "'sftp-files'".into()
                },
            ]
        );
        assert_eq!(Store::attention_settings(&config, Attention::AuthFailed, None), without_pin);
        let with_pin = Store::attention_settings(&config, Attention::ServerIdentityChanged, Some("SHA256:x"));
        assert_eq!(with_pin.len(), 4);
        assert_eq!(with_pin[3].key, b"netvfs/sftp/host_key_seen");
        assert_eq!(with_pin[3].text, "'SHA256:x'");
    }

    /// A fresh folder for a test's database.
    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("netvfs-accounts-store-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A database as libaccounts-glib creates it (see db.rs), with accounts
    /// listed or not for each reason `files_accounts` has.
    fn create(path: &std::path::Path) {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch(crate::db::TEST_SCHEMA).unwrap();
        c.execute_batch(
            "INSERT INTO Services VALUES (1, 'smb-files', 'Files', 'smb', 'netvfs-files'),
                                         (2, 'sftp-files', 'Files', 'sftp', 'netvfs-files'),
                                         (3, 'mail-email', 'Mail', 'mail', 'e-mail'),
                                         (4, 'webdav-files', 'Files', 'webdav', 'netvfs-files');
             -- 1, 5: listed; 2: account disabled; 3: no Files service type;
             -- 4: service disabled; 6: no service setting; 2^32 + 2 reads as 2;
             -- 7: a provider the helper does not hand out.
             INSERT INTO Accounts VALUES (5, 'e', 'sftp', 1), (1, 'a', 'smb', 1), (2, 'b', 'smb', 0),
                                         (3, 'c', 'mail', 1), (4, 'd', 'smb', 1), (6, 'f', 'smb', 1),
                                         (4294967298, 'g', 'smb', 1), (7, 'h', 'webdav', 1);
             INSERT INTO Settings VALUES (1, 0, 'netvfs/host', 's', '''nas'''),
                                         (1, 1, 'enabled', 'b', 'true'), (2, 1, 'enabled', 'b', 'true'),
                                         (3, 3, 'enabled', 'b', 'true'), (4, 1, 'enabled', 'b', 'false'),
                                         (5, 2, 'enabled', 'b', 'true'), (7, 4, 'enabled', 'b', 'true'),
                                         (4294967298, 1, 'enabled', 'b', 'true');",
        )
        .unwrap();
    }

    #[test]
    fn load_reads_the_account() {
        let dir = tempdir("load");
        let path = dir.join("accounts.db");
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(crate::db::TEST_SCHEMA).unwrap();
        c.execute_batch(
            "INSERT INTO Services VALUES (1, 'smb-files', 'Files', 'smb', 'netvfs-files');
             INSERT INTO Accounts VALUES (1, 'alice@nas', 'smb', 1), (2, 'b', 'smb', 1),
                                         (4294967295, 'c', 'smb', 1);
             INSERT INTO Settings VALUES (1, 0, 'netvfs/host', 's', '''nas'''),
                                         (1, 0, 'netvfs/port', 'i', '445'),
                                         (1, 0, 'netvfs/username', 's', '''alice'''),
                                         (1, 0, 'CredentialsId', 'u', '7'),
                                         (1, 0, 'netvfs/attention', 's', '''server-identity-changed'''),
                                         (1, 0, 'netvfs/smb/security_profile', 's', '''signed'''),
                                         (1, 0, 'netvfs/sftp/auth_mode', 's', '''x'''),
                                         (1, 1, 'files_root', 's', ''' photos '''),
                                         (1, 1, 'netvfs/smb/auth_mode', 's', '''x'''),
                                         (2, 0, 'netvfs/host', 's', ''''''),
                                         (4294967295, 0, 'netvfs/host', 's', '''h'''),
                                         (4294967295, 0, 'CredentialsId', 'i', '-2');",
        )
        .unwrap();
        drop(c);
        let store = Store::new(Database::open(&path, false).unwrap());
        assert_eq!(
            store.load(1).unwrap(),
            AccountConfig {
                account_id: 1,
                provider: Some("smb".into()),
                display_name: Some("alice@nas".into()),
                params: ConnectionParams {
                    provider: Some("smb".into()),
                    host: Some("nas".into()),
                    port: 445,
                    username: Some("alice".into()),
                    // Only the provider's own global settings.
                    options: vec![("security_profile".into(), Value::String("signed".into()))],
                    ..ConnectionParams::default()
                },
                files_root: Some("photos".into()),
                credentials_id: 7,
                attention: Attention::ServerIdentityChanged,
            }
        );
        assert_eq!(store.load(2).unwrap_err(), Outcome::failure(Error::Internal, "Account 2 has no server"));
        assert_eq!(store.load(3).unwrap_err(), Outcome::failure(Error::NotFound, "Account 3 does not exist"));
        // A negative id is the account's unsigned id; the credentials id is
        // read as an int, then taken as unsigned.
        let unsigned = store.load(-1).unwrap();
        assert_eq!((unsigned.account_id, unsigned.params.port, unsigned.params.username), (-1, 0, None));
        assert_eq!(unsigned.credentials_id, 4_294_967_294);
        assert_eq!((unsigned.files_root, unsigned.attention), (None, Attention::None));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn files_accounts_golden() {
        let dir = tempdir("list");
        let path = dir.join("accounts.db");
        create(&path);
        let store = Store::new(Database::open(&path, false).unwrap());
        assert_eq!(store.files_accounts().unwrap(), vec![1, 2, 5]);
        assert_eq!(Store::new(Database::empty()).files_accounts().unwrap(), Vec::<i32>::new());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn attention_is_written() {
        let dir = tempdir("attention");
        let path = dir.join("accounts.db");
        create(&path);
        let settings = vec![
            NewSetting { key: b"netvfs/attention".to_vec(), type_string: "s", text: "'auth-failed'".into() },
            NewSetting { key: b"CredentialsNeedUpdate".to_vec(), type_string: "b", text: "true".into() },
        ];
        let failed = Outcome::failure(Error::Internal, "Cannot write the accounts database");
        // Read-only, and no database at all: the write fails.
        let mut read_only = Store::new(Database::open(&path, false).unwrap());
        assert_eq!(read_only.write_attention(1, &settings).unwrap_err(), failed);
        assert_eq!(Store::new(Database::empty()).write_attention(1, &settings).unwrap_err(), failed);

        let mut store = Store::new(Database::open(&path, true).unwrap());
        store.write_attention(1, &settings).unwrap();
        // A negative id is the account's unsigned id.
        store.write_attention(-2, &settings[1..]).unwrap();
        let db = Database::open(&path, false).unwrap();
        let mut global = db.settings(1, 0).unwrap();
        global.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(
            global,
            vec![
                Setting { key: b"CredentialsNeedUpdate".to_vec(), value: Value::Bool(true) },
                Setting { key: b"netvfs/attention".to_vec(), value: Value::String("auth-failed".into()) },
                Setting { key: b"netvfs/host".to_vec(), value: Value::String("nas".into()) },
            ]
        );
        assert_eq!(
            db.settings(4_294_967_294, 0).unwrap(),
            vec![Setting { key: b"CredentialsNeedUpdate".to_vec(), value: Value::Bool(true) }]
        );
        assert_eq!(Store::new(db).load(1).unwrap().attention, Attention::AuthFailed);
        std::fs::remove_dir_all(dir).ok();
    }
}
