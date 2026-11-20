// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`LocationSpec`]: one location a consumer may see, an account with the Files service, and [`Attention`].

use super::state::ConnectionState;
use crate::consent::Level;
use crate::ffi::Params;
use netvfs_bridge_proto::{WireLocation, location_state};
use std::collections::HashMap;
use std::sync::OnceLock;
use zbus::zvariant::{OwnedValue, Str, Value};

/// Why an account needs the user.
pub use crate::accounts::Attention;

/// The id of an account's location.
#[must_use]
pub fn account_location_id(account_id: i32) -> String {
    format!("account:{account_id}")
}

/// One location.
#[derive(Debug, Clone)]
pub struct LocationSpec {
    /// `account:<n>`.
    pub id: String,
    /// The account's libaccounts id.
    pub account_id: i32,
    /// The backend (`sftp`, `smb`, …).
    pub provider: String,
    /// The display name.
    pub name: String,
    /// What a connection needs.
    pub params: Params,
    /// The start folder (`files_root`, the URL's path), protocol bytes.
    pub start_path: Vec<u8>,
    /// An account's attention state.
    pub attention: Attention,
    /// What the consumer may do here.
    pub access: Level,
    url: OnceLock<Option<String>>,
}

impl LocationSpec {
    /// The location of a Files account.
    #[must_use]
    pub fn account(
        account_id: i32,
        provider: impl Into<String>,
        display_name: impl Into<String>,
        params: Params,
        files_root: Vec<u8>,
        attention: Attention,
    ) -> Self {
        Self {
            id: account_location_id(account_id),
            account_id,
            provider: provider.into(),
            name: display_name.into(),
            params,
            start_path: files_root,
            attention,
            access: Level::Full,
            url: OnceLock::new(),
        }
    }

    /// The same location at `level`.
    #[must_use]
    pub fn with_access(mut self, level: Level) -> Self {
        self.access = level;
        self
    }

    /// `<provider>://<host>:<port>` with the host in lower case.
    #[must_use]
    pub fn host_key(&self) -> String {
        format!("{}://{}:{}", self.provider, self.params.host.to_lowercase(), self.params.port)
    }

    /// Whether `other` connects the same way.
    #[must_use]
    pub fn same_connection(&self, other: &Params) -> bool {
        let a = &self.params;
        a.provider == other.provider
            && a.host == other.host
            && a.port == other.port
            && a.username == other.username
            && a.options == other.options
    }

    /// The `a{sv}` of `ListLocations`.
    pub fn info(
        &self,
        state: ConnectionState,
        format_url: impl FnOnce(&Params, &[u8]) -> Option<String>,
    ) -> HashMap<String, OwnedValue> {
        let mut map = HashMap::new();
        map.insert(location_state::KEY.to_owned(), text(state.as_str()));
        if let Some(error) = state.error() {
            map.insert(location_state::ERROR_KEY.to_owned(), text(error.as_str()));
        }
        map.insert("kind".to_owned(), text("account"));
        map.insert("access".to_owned(), text(self.access.as_str()));
        map.insert("host".to_owned(), text(&self.params.host));
        if self.params.port > 0 {
            map.insert("port".to_owned(), OwnedValue::from(self.params.port));
        }
        if !self.params.username.is_empty() {
            map.insert("user".to_owned(), text(&self.params.username));
        }
        if let Ok(path) = OwnedValue::try_from(Value::from(self.start_path.clone())) {
            map.insert("path".to_owned(), path);
        }
        let url =
            self.url.get_or_init(|| format_url(&self.params, &self.start_path).filter(|u| !u.is_empty()));
        if let Some(url) = url {
            map.insert("url".to_owned(), text(url));
        }
        map.insert("accountId".to_owned(), OwnedValue::from(self.account_id));
        if self.attention != Attention::None {
            map.insert("attention".to_owned(), text(self.attention.as_str()));
        }
        map
    }

    /// The `(sssa{sv})` of `ListLocations`, in connection state `state`.
    pub fn wire(
        &self,
        state: ConnectionState,
        format_url: impl FnOnce(&Params, &[u8]) -> Option<String>,
    ) -> WireLocation {
        WireLocation {
            id: self.id.clone(),
            provider: self.provider.clone(),
            name: self.name.clone(),
            info: self.info(state, format_url),
        }
    }
}

fn text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use crate::ffi::Value as Opt;
    use crate::server::args::is_valid_location_id;
    use netvfs_bridge_proto::ErrorName;
    use std::cell::Cell;

    fn params(host: &str, port: i32) -> Params {
        Params {
            provider: "sftp".into(),
            host: host.into(),
            port,
            username: "alice".into(),
            connect_timeout_ms: 1,
            request_timeout_ms: 2,
            ..Params::default()
        }
    }

    fn string(map: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
        map.get(key).map(|v| String::try_from(v.try_clone().unwrap()).unwrap())
    }

    fn int(map: &HashMap<String, OwnedValue>, key: &str) -> Option<i32> {
        map.get(key).map(|v| i32::try_from(v).unwrap())
    }

    #[test]
    fn attention_names_and_errors() {
        assert_eq!(Attention::None.as_str(), "");
        assert_eq!(Attention::AuthFailed.as_str(), "auth-failed");
        assert_eq!(Attention::ServerIdentityChanged.as_str(), "server-identity-changed");
        assert_eq!(Attention::default(), Attention::None);
        assert_eq!(Attention::for_error(ErrorName::AuthFailed), Attention::AuthFailed);
        assert_eq!(Attention::for_error(ErrorName::ServerIdentityChanged), Attention::ServerIdentityChanged);
        assert_eq!(Attention::for_error(ErrorName::ServerIdentityUnknown), Attention::ServerIdentityChanged);
        assert_eq!(Attention::for_error(ErrorName::Timeout), Attention::None);
        assert_eq!(Attention::for_error(ErrorName::PermissionDenied), Attention::None);
    }

    #[test]
    fn ids_and_host_keys() {
        assert_eq!(account_location_id(12), "account:12");
        assert!(is_valid_location_id(&account_location_id(i32::MIN)));
        let account = LocationSpec::account(
            7,
            "sftp",
            "Seven",
            params("Host.EXAMPLE", 2222),
            b"/r".to_vec(),
            Attention::None,
        );
        assert_eq!(account.id, "account:7");
        assert_eq!(account.account_id, 7);
        assert_eq!((account.provider.as_str(), account.name.as_str()), ("sftp", "Seven"));
        assert_eq!(account.start_path, b"/r");
        assert_eq!(account.host_key(), "sftp://host.example:2222");
    }

    #[test]
    fn same_connection_compares_what_connects() {
        let spec = LocationSpec::account(1, "sftp", "A", params("h", 22), Vec::new(), Attention::None);
        let mut other = params("h", 22);
        assert!(spec.same_connection(&other));
        other.connect_timeout_ms = 99;
        other.request_timeout_ms = 99;
        assert!(spec.same_connection(&other));
        for change in [
            |p: &mut Params| p.provider = "smb".into(),
            |p: &mut Params| p.host = "H".into(),
            |p: &mut Params| p.port = 23,
            |p: &mut Params| p.username = "bob".into(),
            |p: &mut Params| drop(p.options.insert("share".into(), Opt::Str("x".into()))),
        ] {
            let mut changed = params("h", 22);
            change(&mut changed);
            assert!(!spec.same_connection(&changed), "{changed:?}");
        }
    }

    #[test]
    fn info_of_an_account() {
        let mut spec = LocationSpec::account(
            5,
            "sftp",
            "Five",
            params("srv", 2222),
            b"/home/\xff".to_vec(),
            Attention::AuthFailed,
        )
        .with_access(Level::ReadAdd);
        let asked = Cell::new(0);
        let format = |p: &Params, path: &[u8]| {
            asked.set(asked.get() + 1);
            Some(format!("{}://{}{}", p.provider, p.host, String::from_utf8_lossy(path)))
        };
        let info = spec.info(ConnectionState::Failed(ErrorName::AuthFailed), format);
        assert_eq!(string(&info, "kind").as_deref(), Some("account"));
        assert_eq!(string(&info, "host").as_deref(), Some("srv"));
        assert_eq!(int(&info, "port"), Some(2222));
        assert_eq!(string(&info, "user").as_deref(), Some("alice"));
        assert_eq!(Vec::<u8>::try_from(info["path"].try_clone().unwrap()).unwrap(), b"/home/\xff");
        assert_eq!(string(&info, "url").as_deref(), Some("sftp://srv/home/\u{fffd}"));
        assert_eq!(int(&info, "accountId"), Some(5));
        assert_eq!(string(&info, "attention").as_deref(), Some("auth-failed"));
        assert_eq!(string(&info, "state").as_deref(), Some("failed"));
        assert_eq!(string(&info, "stateError").as_deref(), Some("AuthFailed"));
        assert_eq!(string(&info, "access").as_deref(), Some("read-add"));
        assert_eq!(info.len(), 11);
        let again = spec.info(ConnectionState::Connected, |_: &Params, _: &[u8]| -> Option<String> {
            panic!("formatted twice")
        });
        assert_eq!(string(&again, "url").as_deref(), Some("sftp://srv/home/\u{fffd}"));
        assert_eq!(asked.get(), 1);
        assert_eq!(string(&again, "state").as_deref(), Some("connected"));
        assert!(!again.contains_key("stateError"));
        spec = LocationSpec::account(5, "sftp", "Five", params("srv", 0), Vec::new(), Attention::None);
        spec.params.username.clear();
        let info = spec.info(ConnectionState::Disconnected, |_: &Params, _: &[u8]| None);
        let mut keys: Vec<&str> = info.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["access", "accountId", "host", "kind", "path", "state"]);
        assert_eq!(string(&info, "access").as_deref(), Some("full"));
        assert_eq!(string(&info, "state").as_deref(), Some("disconnected"));
    }

    #[test]
    fn info_without_url_and_wire() {
        let spec = LocationSpec::account(2, "sftp", "Two", params("h", 21), b"/x".to_vec(), Attention::None);
        let info = spec.info(ConnectionState::Connecting, |_: &Params, _: &[u8]| Some(String::new()));
        assert_eq!(string(&info, "state").as_deref(), Some("connecting"));
        assert!(!info.contains_key("url") && !info.contains_key("attention"));
        let failed = ConnectionState::Failed(ErrorName::NetworkUnreachable);
        let wire = spec.wire(failed, |_: &Params, _: &[u8]| Some("sftp://h:21/x".into()));
        assert_eq!(
            (wire.id.as_str(), wire.provider.as_str(), wire.name.as_str()),
            ("account:2", "sftp", "Two")
        );
        assert_eq!(string(&wire.info, "state").as_deref(), Some("failed"));
        assert_eq!(string(&wire.info, "stateError").as_deref(), Some("NetworkUnreachable"));
        assert!(!wire.info.contains_key("url"));
        let fresh = LocationSpec::account(2, "sftp", "Two", params("h", 21), b"/x".to_vec(), Attention::None);
        let wire =
            fresh.wire(ConnectionState::Connected, |_: &Params, _: &[u8]| Some("sftp://h:21/x".into()));
        assert_eq!(string(&wire.info, "url").as_deref(), Some("sftp://h:21/x"));
    }
}
