// SPDX-License-Identifier: LGPL-2.1-or-later
//! The commands of netvfs-accounts (SPEC-v2 XB-2a), answered as
//! `AccountsHelper::serve` of the C++ bridge (netvfs 0.4) did:
//!
//! ```text
//! netvfs-accounts list                          the Files accounts (XA-1)
//! netvfs-accounts files <id>                    what a connection needs, policy checked (XA-4)
//! netvfs-accounts attention <id> <state> [pin]  records auth-failed or server-identity-changed (XB-14)
//! ```

use crate::db::{Database, Environment, NewSetting, PrivilegedOwner, Unusable};
use crate::policy::{ConnectionParams, check_files_policy, secret_optional};
use crate::qvariant;
use crate::store::{Attention, Store, normalize, unusable_outcome};
use crate::wire::{Error, Outcome, Stream};

const USAGE: &str = "Usage: netvfs-accounts list | files <id> | attention <id> <state> [pin]";

/// A request, from the arguments without the program name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// The Files accounts (`list`).
    List,
    /// What a connection needs (`files <id>`).
    Files(String),
    /// Records an attention state (`attention <id> <state> [pin]`).
    Attention {
        /// The account id, as given.
        id: String,
        /// The state, as given.
        state: String,
        /// The host key to remember (`host_key_seen`), if given.
        pin: Option<String>,
    },
    /// Anything else: the usage message.
    Usage,
}

impl Command {
    /// The command the arguments name; anything else is `Usage`.
    #[must_use]
    pub fn parse(arguments: &[String]) -> Self {
        match arguments {
            [c] if c == "list" => Self::List,
            [c, id] if c == "files" => Self::Files(id.clone()),
            [c, id, state] if c == "attention" => {
                Self::Attention { id: id.clone(), state: state.clone(), pin: None }
            }
            [c, id, state, pin] if c == "attention" => {
                Self::Attention { id: id.clone(), state: state.clone(), pin: Some(pin.clone()) }
            }
            _ => Self::Usage,
        }
    }

    fn writes(&self) -> bool {
        matches!(self, Self::Attention { .. })
    }
}

/// A change to announce on the session bus, as libaccounts-glib's writers
/// do (dbus.rs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The account's id.
    pub account_id: u32,
    /// The account's provider.
    pub provider: String,
    /// The settings written.
    pub settings: Vec<NewSetting>,
}

/// The answer, and the change made, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// The answer for stdout.
    pub answer: Vec<u8>,
    /// The change to announce, if any.
    pub change: Option<Change>,
}

impl Served {
    fn answer(answer: Vec<u8>) -> Self {
        Self { answer, change: None }
    }

    fn failure(outcome: &Outcome) -> Self {
        Self::answer(Stream::answer(outcome).into_bytes())
    }
}

/// Opens the database the environment names.
///
/// # Errors
/// When the database cannot be found or opened.
pub fn open(env: &Environment, owner: &dyn PrivilegedOwner, writable: bool) -> Result<Database, Unusable> {
    let path = env.location().database(owner)?;
    Database::open(&path, writable)
}

/// Answers `arguments`. Always an answer, also for an error.
#[must_use]
pub fn serve(arguments: &[String], env: &Environment, owner: &dyn PrivilegedOwner) -> Served {
    let command = Command::parse(arguments);
    match open(env, owner, command.writes()) {
        Ok(db) => serve_with(&command, Store::new(db)),
        Err(e) => Served::failure(&unusable_outcome(&e)),
    }
}

/// Answers `command` from `store`.
#[must_use]
pub fn serve_with(command: &Command, mut store: Store) -> Served {
    match command {
        Command::List => serve_list(&store),
        Command::Files(id) => serve_files(&store, id),
        Command::Attention { id, state, pin } => serve_attention(&mut store, id, state, pin.as_deref()),
        Command::Usage => Served::failure(&Outcome::failure(Error::Unsupported, USAGE)),
    }
}

fn write_params(s: &mut Stream, p: &ConnectionParams) {
    s.string(p.provider.as_deref());
    s.string(p.host.as_deref());
    s.i32(p.port);
    s.string(p.username.as_deref());
    s.variant_map(&p.options);
    s.i32(p.connect_timeout_ms);
    s.i32(p.request_timeout_ms);
}

/// The listed account `id` (XA-1), loaded.
fn load_listed(store: &Store, id: &str) -> Result<crate::store::AccountConfig, Outcome> {
    let not_found = || Outcome::failure(Error::NotFound, "No such account");
    let account_id = qvariant::to_int(id).filter(|i| *i > 0).ok_or_else(not_found)?;
    let listed = store.files_accounts().map_err(|e| unusable_outcome(&e))?;
    if !listed.contains(&account_id) {
        return Err(not_found());
    }
    store.load(account_id)
}

fn serve_list(store: &Store) -> Served {
    let ids = match store.files_accounts() {
        Ok(ids) => ids,
        Err(e) => return Served::failure(&unusable_outcome(&e)),
    };
    let accounts: Vec<_> = ids.into_iter().filter_map(|id| store.load(id).ok()).collect();
    let mut s = Stream::answer(&Outcome::success());
    s.i32(i32::try_from(accounts.len()).unwrap_or(i32::MAX));
    for a in &accounts {
        s.i32(a.account_id);
        s.string(a.provider.as_deref());
        s.string(a.display_name.as_deref());
        write_params(&mut s, &a.params);
        s.string(normalize(a.files_root.as_deref()).flatten().as_deref());
        s.i32(a.attention as i32);
    }
    Served::answer(s.into_bytes())
}

fn serve_files(store: &Store, id: &str) -> Served {
    let config = match load_listed(store, id) {
        Ok(config) => config,
        Err(outcome) => return Served::failure(&outcome),
    };
    // XA-4: refused before the secret is read.
    let policy = check_files_policy(&config.params);
    if !policy.ok() {
        return Served::failure(&policy);
    }
    let mut s = Stream::answer(&Outcome::success());
    write_params(&mut s, &config.params);
    s.u32(config.credentials_id);
    s.bool(secret_optional(&config.params));
    Served::answer(s.into_bytes())
}

fn serve_attention(store: &mut Store, id: &str, state: &str, pin: Option<&str>) -> Served {
    // XB-14 records attention; clearing it is the update flow's (Settings).
    let attention = Attention::from_qstring(Some(state));
    if attention == Attention::None {
        return Served::failure(&Outcome::failure(Error::Unsupported, "Unknown attention state"));
    }
    let config = match load_listed(store, id) {
        Ok(config) => config,
        Err(outcome) => return Served::failure(&outcome),
    };
    let settings = Store::attention_settings(&config, attention, pin);
    if let Err(outcome) = store.write_attention(config.account_id, &settings) {
        return Served::failure(&outcome);
    }
    Served {
        answer: Stream::answer(&Outcome::success()).into_bytes(),
        change: Some(Change {
            account_id: u32::from_ne_bytes(config.account_id.to_ne_bytes()),
            provider: config.provider.unwrap_or_default(),
            settings,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn commands() {
        assert_eq!(Command::parse(&args(&["list"])), Command::List);
        assert_eq!(Command::parse(&args(&["files", "7"])), Command::Files("7".into()));
        assert_eq!(
            Command::parse(&args(&["attention", "7", "auth-failed"])),
            Command::Attention { id: "7".into(), state: "auth-failed".into(), pin: None }
        );
        assert_eq!(
            Command::parse(&args(&["attention", "7", "auth-failed", ""])),
            Command::Attention { id: "7".into(), state: "auth-failed".into(), pin: Some(String::new()) }
        );
        for bad in [
            &[][..],
            &["list", "x"],
            &["files"],
            &["files", "1", "2"],
            &["files", "1", "2", "3"],
            &["attention", "1"],
            &["attention", "1", "a", "b", "c"],
            &["secret", "1"],
            &["LIST"],
        ] {
            assert_eq!(Command::parse(&args(bad)), Command::Usage, "{bad:?}");
        }
        assert!(Command::Attention { id: String::new(), state: String::new(), pin: None }.writes());
        assert!(!Command::List.writes());
        assert!(!Command::Usage.writes());
    }

    #[test]
    fn empty_database() {
        let empty = || Store::new(Database::empty());
        let list = serve_with(&Command::List, empty());
        let mut expected = Stream::answer(&Outcome::success());
        expected.i32(0);
        assert_eq!(list, Served { answer: expected.into_bytes(), change: None });
        let not_found = Stream::answer(&Outcome::failure(Error::NotFound, "No such account")).into_bytes();
        assert_eq!(serve_with(&Command::Files("1".into()), empty()).answer, not_found);
        let attention = Command::Attention { id: "1".into(), state: "auth-failed".into(), pin: None };
        assert_eq!(serve_with(&attention, empty()), Served::answer(not_found));
        let unknown = Command::Attention { id: "1".into(), state: "none".into(), pin: None };
        assert_eq!(
            serve_with(&unknown, empty()).answer,
            Stream::answer(&Outcome::failure(Error::Unsupported, "Unknown attention state")).into_bytes()
        );
        assert_eq!(
            serve_with(&Command::Usage, empty()).answer,
            Stream::answer(&Outcome::failure(Error::Unsupported, USAGE)).into_bytes()
        );
    }

    /// A database with three listed accounts: 1 usable, 2 refused by the
    /// policy, and 2^32, whose id reads as 0; 5 is a WebDAV account with its
    /// Files service enabled, which is not handed out. Its path.
    fn listed_accounts(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("netvfs-accounts-serve-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.db");
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(crate::db::TEST_SCHEMA).unwrap();
        c.execute_batch(
            "INSERT INTO Services VALUES (1, 'smb-files', 'Files', 'smb', 'netvfs-files'),
                                         (2, 'webdav-files', 'Files', 'webdav', 'netvfs-files');
             INSERT INTO Accounts VALUES (1, 'alice@nas', 'smb', 1), (2, 'b', 'smb', 1),
                                         (4294967296, 'z', 'smb', 1), (5, 'dav', 'webdav', 1);
             INSERT INTO Settings VALUES (1, 0, 'netvfs/host', 's', '''nas'''),
                                         (1, 0, 'netvfs/port', 'i', '445'),
                                         (1, 0, 'netvfs/username', 's', '''alice'''),
                                         (1, 0, 'CredentialsId', 'u', '7'),
                                         (1, 0, 'netvfs/smb/security_profile', 's', '''signed'''),
                                         (1, 1, 'enabled', 'b', 'true'),
                                         (1, 1, 'files_root', 's', '''//photos/'''),
                                         (2, 0, 'netvfs/host', 's', '''old'''),
                                         (2, 0, 'netvfs/attention', 's', '''auth-failed'''),
                                         (2, 0, 'netvfs/smb/security_profile', 's', '''bogus'''),
                                         (2, 1, 'enabled', 'b', 'true'),
                                         (4294967296, 0, 'netvfs/host', 's', '''zero'''),
                                         (4294967296, 1, 'enabled', 'b', 'true'),
                                         (5, 0, 'netvfs/host', 's', '''dav'''),
                                         (5, 2, 'enabled', 'b', 'true');",
        )
        .unwrap();
        drop(c);
        path
    }

    fn read_only(path: &std::path::Path) -> Store {
        Store::new(Database::open(path, false).unwrap())
    }

    /// The connection parameters of an smb account whose one option is
    /// `security_profile`, as written.
    fn write_params_of(s: &mut Stream, host: &str, port: i32, username: Option<&str>, profile: &str) {
        s.string(Some("smb"));
        s.string(Some(host));
        s.i32(port);
        s.string(username);
        s.variant_map(&[("security_profile".into(), qvariant::Value::String(profile.into()))]);
        s.i32(15_000);
        s.i32(60_000);
    }

    #[test]
    fn files_answers() {
        let path = listed_accounts("files");
        let files = |id: &str| serve_with(&Command::Files(id.into()), read_only(&path));
        let mut expected = Stream::answer(&Outcome::success());
        write_params_of(&mut expected, "nas", 445, Some("alice"), "signed");
        expected.u32(7);
        expected.bool(false);
        assert_eq!(files("1"), Served::answer(expected.into_bytes()));
        let refused = Outcome::failure(Error::SecurityPolicy, "Unknown SMB security profile \"bogus\"");
        assert_eq!(files("2"), Served::failure(&refused));
        // 0 is no account id, though a listed account reads as 0.
        let not_found = Served::failure(&Outcome::failure(Error::NotFound, "No such account"));
        assert_eq!(files("0"), not_found);
        assert_eq!(files("3"), not_found);
        assert_eq!(files("5"), not_found);
        assert_eq!(files("x"), not_found);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn list_answers() {
        let path = listed_accounts("list");
        let mut expected = Stream::answer(&Outcome::success());
        // Account 0 is listed but cannot be loaded: left out.
        expected.i32(2);
        expected.i32(1);
        expected.string(Some("smb"));
        expected.string(Some("alice@nas"));
        write_params_of(&mut expected, "nas", 445, Some("alice"), "signed");
        expected.string(Some("/photos"));
        expected.i32(Attention::None as i32);
        expected.i32(2);
        expected.string(Some("smb"));
        expected.string(Some("b"));
        write_params_of(&mut expected, "old", 0, None, "bogus");
        expected.string(None);
        expected.i32(Attention::AuthFailed as i32);
        assert_eq!(serve_with(&Command::List, read_only(&path)), Served::answer(expected.into_bytes()));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    struct NoOwner;
    impl PrivilegedOwner for NoOwner {
        fn privileged_ids(&self) -> Option<(u32, u32)> {
            None
        }
    }

    #[test]
    fn unusable_database() {
        let env = Environment { accounts: Some("/dev/null/accounts".into()), ..Environment::default() };
        let served = serve(&args(&["list"]), &env, &NoOwner);
        assert_eq!(served.change, None);
        // PermissionDenied
        assert_eq!(served.answer[..4], [0, 0, 0, 8]);
        // Also before the usage is checked, as the C++ helper did.
        assert_eq!(serve(&args(&["bogus"]), &env, &NoOwner).answer[..4], [0, 0, 0, 8]);
        let missing =
            Environment { accounts: Some("/nonexistent/accounts".into()), ..Environment::default() };
        assert_eq!(serve(&args(&["bogus"]), &missing, &NoOwner).answer[..4], [0, 0, 0, 12]);
    }
}
