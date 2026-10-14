// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`LocationSpec`]: one location a consumer may see (XB-7), an account
//! with the Files service or an ad-hoc location it created (port of
//! `location.cpp`), and [`Attention`] (XB-14).

use crate::ffi::Params;
use netvfs_bridge_proto::WireLocation;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use zbus::zvariant::{OwnedValue, Str, Value};
use zeroize::Zeroizing;

/// Why an account needs the user (XB-14): the platform part's type.
pub use crate::accounts::Attention;

/// Which kind of location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocationKind {
    /// A netvfs account with the Files service enabled.
    Account {
        /// Its libaccounts id.
        account_id: i32,
    },
    /// An ad-hoc location this consumer created (`ConnectAdHoc`).
    AdHoc,
}

/// The secret a consumer gave for an ad-hoc location (XB-16), held for the
/// connections of its pool and wiped when the location goes away. Shared
/// by every copy of the spec, so one wipe reaches all of them.
pub struct AdHocSecret {
    user: String,
    secret: Mutex<Zeroizing<Vec<u8>>>,
}

impl AdHocSecret {
    /// The credentials `user` / `secret`.
    #[must_use]
    pub fn new(user: impl Into<String>, secret: Zeroizing<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self { user: user.into(), secret: Mutex::new(secret) })
    }

    /// The user name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// A copy of the secret (wiped when dropped); empty after a wipe.
    #[must_use]
    pub fn secret(&self) -> Zeroizing<Vec<u8>> {
        self.secret.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Wipes the secret (the location went away).
    pub fn wipe(&self) {
        *self.secret.lock().unwrap_or_else(PoisonError::into_inner) = Zeroizing::new(Vec::new());
    }
}

impl fmt::Debug for AdHocSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.secret.lock().unwrap_or_else(PoisonError::into_inner).len();
        f.debug_struct("AdHocSecret").field("user", &self.user).field("secret_bytes", &len).finish()
    }
}

/// The id of an account's location: `account:<n>`.
#[must_use]
pub fn account_location_id(account_id: i32) -> String {
    format!("account:{account_id}")
}

/// The id of the `n`th ad-hoc location: `adhoc:<n>`.
#[must_use]
pub fn ad_hoc_location_id(n: u64) -> String {
    format!("adhoc:{n}")
}

/// One location (`LocationSpec`). The parameters never hold a secret.
#[derive(Debug, Clone)]
pub struct LocationSpec {
    /// `account:<n>` or `adhoc:<n>`.
    pub id: String,
    /// Account or ad hoc.
    pub kind: LocationKind,
    /// The backend (`sftp`, `smb`, `webdav`, …).
    pub provider: String,
    /// The display name.
    pub name: String,
    /// What a connection needs (for an account the listed parameters;
    /// connections use what the helper's `files` answer gives).
    pub params: Params,
    /// The start folder (`files_root`, the URL's path), protocol bytes.
    pub start_path: Vec<u8>,
    /// An account's attention state.
    pub attention: Attention,
    /// Ad hoc only: the secret the consumer gave.
    pub ad_hoc_secret: Option<Arc<AdHocSecret>>,
    /// `info()`'s URL, formatted once per spec.
    url: OnceLock<Option<String>>,
}

impl LocationSpec {
    /// The location of a Files account (`specFor`).
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
            kind: LocationKind::Account { account_id },
            provider: provider.into(),
            name: display_name.into(),
            params,
            start_path: files_root,
            attention,
            ad_hoc_secret: None,
            url: OnceLock::new(),
        }
    }

    /// An ad-hoc location with the id `id` (from
    /// [`LocationBook::reserve_ad_hoc_id`](super::book::LocationBook::reserve_ad_hoc_id)).
    #[must_use]
    pub fn ad_hoc(
        id: impl Into<String>,
        name: impl Into<String>,
        params: Params,
        start_path: Vec<u8>,
        secret: Option<Arc<AdHocSecret>>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: LocationKind::AdHoc,
            provider: params.provider.clone(),
            name: name.into(),
            params,
            start_path,
            attention: Attention::None,
            ad_hoc_secret: secret,
            url: OnceLock::new(),
        }
    }

    /// The account's id; `None` for an ad-hoc location.
    #[must_use]
    pub const fn account_id(&self) -> Option<i32> {
        match self.kind {
            LocationKind::Account { account_id } => Some(account_id),
            LocationKind::AdHoc => None,
        }
    }

    /// `<provider>://<host>:<port>` with the host in lower case: the
    /// per-host limit (XB-12) and the known_hosts key (XB-14).
    #[must_use]
    pub fn host_key(&self) -> String {
        format!("{}://{}:{}", self.provider, self.params.host.to_lowercase(), self.params.port)
    }

    /// Whether `other` connects the same way (`sameConnection`: provider,
    /// host, port, user and options; not the timeouts).
    #[must_use]
    pub fn same_connection(&self, other: &Params) -> bool {
        let a = &self.params;
        a.provider == other.provider
            && a.host == other.host
            && a.port == other.port
            && a.username == other.username
            && a.options == other.options
    }

    /// The `a{sv}` of `ListLocations`: `kind`, `host`, `port` (when set),
    /// `user` (when set), `path`, `url` (when `format_url` gives one; asked
    /// once per spec), and for accounts `accountId` and `attention` (when
    /// set).
    pub fn info(
        &self,
        format_url: impl FnOnce(&Params, &[u8]) -> Option<String>,
    ) -> HashMap<String, OwnedValue> {
        let mut map = HashMap::new();
        let kind = if self.account_id().is_some() { "account" } else { "adhoc" };
        map.insert("kind".to_owned(), text(kind));
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
        if let Some(account_id) = self.account_id() {
            map.insert("accountId".to_owned(), OwnedValue::from(account_id));
            if self.attention != Attention::None {
                map.insert("attention".to_owned(), text(self.attention.as_str()));
            }
        }
        map
    }

    /// The `(sssa{sv})` of `ListLocations`.
    pub fn wire(&self, format_url: impl FnOnce(&Params, &[u8]) -> Option<String>) -> WireLocation {
        WireLocation {
            id: self.id.clone(),
            provider: self.provider.clone(),
            name: self.name.clone(),
            info: self.info(format_url),
        }
    }
}

/// A string value.
fn text(s: &str) -> OwnedValue {
    OwnedValue::from(Str::from(s.to_owned()))
}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;
    use crate::ffi::Value as Opt;
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
    fn ids_kinds_and_host_keys() {
        assert_eq!(account_location_id(12), "account:12");
        assert_eq!(ad_hoc_location_id(3), "adhoc:3");
        let account = LocationSpec::account(
            7,
            "sftp",
            "Seven",
            params("Host.EXAMPLE", 2222),
            b"/r".to_vec(),
            Attention::None,
        );
        assert_eq!(account.id, "account:7");
        assert_eq!(account.kind, LocationKind::Account { account_id: 7 });
        assert_eq!(account.account_id(), Some(7));
        assert_eq!((account.provider.as_str(), account.name.as_str()), ("sftp", "Seven"));
        assert_eq!(account.start_path, b"/r");
        assert_eq!(account.host_key(), "sftp://host.example:2222");
        let adhoc = LocationSpec::ad_hoc("adhoc:1", "Mine", params("h", 0), Vec::new(), None);
        assert_eq!((adhoc.kind, adhoc.account_id()), (LocationKind::AdHoc, None));
        assert_eq!(adhoc.attention, Attention::None);
        assert_eq!(adhoc.host_key(), "sftp://h:0");
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
        );
        let asked = Cell::new(0);
        let format = |p: &Params, path: &[u8]| {
            asked.set(asked.get() + 1);
            Some(format!("{}://{}{}", p.provider, p.host, String::from_utf8_lossy(path)))
        };
        let info = spec.info(format);
        assert_eq!(string(&info, "kind").as_deref(), Some("account"));
        assert_eq!(string(&info, "host").as_deref(), Some("srv"));
        assert_eq!(int(&info, "port"), Some(2222));
        assert_eq!(string(&info, "user").as_deref(), Some("alice"));
        assert_eq!(Vec::<u8>::try_from(info["path"].try_clone().unwrap()).unwrap(), b"/home/\xff");
        assert_eq!(string(&info, "url").as_deref(), Some("sftp://srv/home/\u{fffd}"));
        assert_eq!(int(&info, "accountId"), Some(5));
        assert_eq!(string(&info, "attention").as_deref(), Some("auth-failed"));
        assert_eq!(info.len(), 8);
        // The URL is formatted once per spec.
        let again = spec.info(|_: &Params, _: &[u8]| -> Option<String> { panic!("formatted twice") });
        assert_eq!(string(&again, "url").as_deref(), Some("sftp://srv/home/\u{fffd}"));
        assert_eq!(asked.get(), 1);
        // No attention, no port, no user, no URL.
        spec = LocationSpec::account(5, "sftp", "Five", params("srv", 0), Vec::new(), Attention::None);
        spec.params.username.clear();
        let info = spec.info(|_: &Params, _: &[u8]| None);
        let mut keys: Vec<&str> = info.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["accountId", "host", "kind", "path"]);
    }

    #[test]
    fn info_of_an_ad_hoc_location_and_wire() {
        let spec = LocationSpec::ad_hoc("adhoc:2", "Two", params("h", 21), b"/x".to_vec(), None);
        let info = spec.info(|_: &Params, _: &[u8]| Some(String::new()));
        assert_eq!(string(&info, "kind").as_deref(), Some("adhoc"));
        // An empty URL is no URL; ad-hoc locations have no account id.
        assert!(
            !info.contains_key("url") && !info.contains_key("accountId") && !info.contains_key("attention")
        );
        let wire = spec.wire(|_: &Params, _: &[u8]| Some("sftp://h:21/x".into()));
        assert_eq!(
            (wire.id.as_str(), wire.provider.as_str(), wire.name.as_str()),
            ("adhoc:2", "sftp", "Two")
        );
        // The cache holds what the first call gave: no URL.
        assert!(!wire.info.contains_key("url"));
        let fresh = LocationSpec::ad_hoc("adhoc:2", "Two", params("h", 21), b"/x".to_vec(), None);
        let wire = fresh.wire(|_: &Params, _: &[u8]| Some("sftp://h:21/x".into()));
        assert_eq!(string(&wire.info, "url").as_deref(), Some("sftp://h:21/x"));
    }

    #[test]
    fn ad_hoc_secrets_are_shared_and_wiped() {
        let secret = AdHocSecret::new("u", Zeroizing::new(b"pw".to_vec()));
        let spec =
            LocationSpec::ad_hoc("adhoc:1", "n", params("h", 0), Vec::new(), Some(Arc::clone(&secret)));
        let copy = spec.clone();
        assert_eq!(copy.ad_hoc_secret.as_ref().unwrap().user(), "u");
        assert_eq!(copy.ad_hoc_secret.as_ref().unwrap().secret().as_slice(), b"pw");
        let shown = format!("{secret:?}");
        assert!(shown.contains("secret_bytes: 2") && !shown.contains("pw"), "{shown}");
        spec.ad_hoc_secret.as_ref().unwrap().wipe();
        assert!(copy.ad_hoc_secret.as_ref().unwrap().secret().is_empty());
        assert!(format!("{secret:?}").contains("secret_bytes: 0"));
    }
}
