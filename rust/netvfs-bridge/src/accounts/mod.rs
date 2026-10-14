// SPDX-License-Identifier: LGPL-2.1-or-later
//! The accounts (SPEC-v2 XB-2a, XB-7): netvfs accounts whose Files service
//! is enabled. Only `/usr/libexec/netvfs/netvfs-accounts` (setgid
//! `privileged`) can read the accounts database; the bridge runs it once per
//! request ([`helper`]), reads its answer ([`qds`]) and refreshes when a
//! writer announces a change on the session bus ([`watch`]).
//!
//! Secrets stay with signond: [`FilesAccess`] carries the credentials id,
//! which the C++ side looks up.

pub mod helper;
pub mod qds;
pub mod watch;

use crate::status::Status;
use netvfs_bridge_proto::ErrorName;
use std::future::Future;

/// A `QVariant` as the helper writes one (`ConnectionParams::options`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An invalid `QVariant`.
    Invalid,
    /// `bool`.
    Bool(bool),
    /// `int`.
    Int(i32),
    /// `uint`.
    UInt(u32),
    /// `qlonglong`.
    LongLong(i64),
    /// `qulonglong`.
    ULongLong(u64),
    /// `QString`.
    String(String),
    /// `QStringList`.
    StringList(Vec<String>),
    /// `QByteArray`.
    ByteArray(Vec<u8>),
    /// `QVariantMap`: keys unique, in `QMap` order (by UTF-16 code units).
    Map(Vec<(String, Self)>),
}

/// `NetVfs::ConnectionParams`: what a connection needs, never a secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionParams {
    /// The backend, `sftp`, `smb`, ...
    pub provider: String,
    /// The server.
    pub host: String,
    /// `0`: the protocol's default.
    pub port: i32,
    /// The user name.
    pub username: String,
    /// Provider options: keys unique, in `QMap` order.
    pub options: Vec<(String, Value)>,
    /// Milliseconds, `0`: the default.
    pub connect_timeout_ms: i32,
    /// Milliseconds, `0`: the default.
    pub request_timeout_ms: i32,
}

/// Why an account needs the user (XB-14), as Buteo records it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Attention {
    /// Nothing to do.
    #[default]
    None,
    /// The credentials were refused: `auth-failed`.
    AuthFailed,
    /// The server's identity changed: `server-identity-changed`.
    ServerIdentityChanged,
}

impl Attention {
    /// `attentionToString`: the stored value, empty for `None`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::AuthFailed => "auth-failed",
            Self::ServerIdentityChanged => "server-identity-changed",
        }
    }

    /// `attentionForError`: the state a failed connection leaves (an
    /// unknown identity counts as changed: the account had a pin).
    #[must_use]
    pub const fn for_error(name: ErrorName) -> Self {
        match name {
            ErrorName::AuthFailed => Self::AuthFailed,
            ErrorName::ServerIdentityChanged | ErrorName::ServerIdentityUnknown => {
                Self::ServerIdentityChanged
            }
            _ => Self::None,
        }
    }
}

/// A netvfs account with the Files service enabled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountLocation {
    /// The libaccounts id.
    pub account_id: i32,
    /// The provider of the account.
    pub provider: String,
    /// The account's display name.
    pub display_name: String,
    /// What a connection needs.
    pub params: ConnectionParams,
    /// The start folder as protocol bytes (`Names::encode`).
    pub files_root: Vec<u8>,
    /// Whether the account needs the user.
    pub attention: Attention,
}

/// What `files <id>` answers, ready for the secret lookup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilesAccess {
    /// `paramsForService(Files)`.
    pub params: ConnectionParams,
    /// The signond identity holding the secret.
    pub credentials_id: u32,
    /// A connection may go on without a secret (XA-7).
    pub secret_optional: bool,
}

impl Value {
    /// The value as the C ABI carries it (`nvb_value`): integers widen to
    /// 64 bits; `None` for what it cannot carry (an invalid value, a
    /// `qulonglong` above `i64::MAX`, a nested map: design §6.10).
    #[must_use]
    pub fn to_ffi(&self) -> Option<crate::ffi::Value> {
        use crate::ffi::Value as V;
        match self {
            Self::Invalid | Self::Map(_) => None,
            Self::Bool(b) => Some(V::Bool(*b)),
            Self::Int(i) => Some(V::Int(i64::from(*i))),
            Self::UInt(u) => Some(V::Int(i64::from(*u))),
            Self::LongLong(i) => Some(V::Int(*i)),
            Self::ULongLong(u) => i64::try_from(*u).ok().map(V::Int),
            Self::String(s) => Some(V::Str(s.clone())),
            Self::StringList(l) => Some(V::StrList(l.clone())),
            Self::ByteArray(b) => Some(V::Bytes(b.clone())),
        }
    }
}

impl ConnectionParams {
    /// The parameters as the C ABI carries them; options it cannot carry
    /// are left out with a warning (design §6.10: none exist today).
    #[must_use]
    pub fn to_ffi(&self) -> crate::ffi::Params {
        let options = self
            .options
            .iter()
            .filter_map(|(key, value)| {
                let converted = value.to_ffi();
                if converted.is_none() {
                    crate::log::warning(format_args!("The account option {key} is left out: no such value"));
                }
                converted.map(|v| (key.clone(), v))
            })
            .collect();
        crate::ffi::Params {
            provider: self.provider.clone(),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            options,
            connect_timeout_ms: self.connect_timeout_ms,
            request_timeout_ms: self.request_timeout_ms,
        }
    }
}

/// The accounts database, behind a trait so that tests run without the
/// helper.
pub trait AccountDirectory {
    /// The Files accounts; none when they cannot be listed (logged).
    fn list(&self) -> impl Future<Output = Vec<AccountLocation>>;
    /// What a connection to the listed account `id` needs, policy checked
    /// (XA-4).
    fn files(&self, id: i32) -> impl Future<Output = Result<FilesAccess, Status>>;
    /// Records `attention` for `id` with the pin seen (XB-14), as Buteo
    /// does after a failed run; failures are logged.
    fn set_attention(&self, id: i32, attention: Attention, pin: &str) -> impl Future<Output = ()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attention_names() {
        assert_eq!(Attention::None.as_str(), "");
        assert_eq!(Attention::AuthFailed.as_str(), "auth-failed");
        assert_eq!(Attention::ServerIdentityChanged.as_str(), "server-identity-changed");
        assert_eq!(Attention::default(), Attention::None);
        assert_eq!(Attention::for_error(ErrorName::AuthFailed), Attention::AuthFailed);
        assert_eq!(Attention::for_error(ErrorName::ServerIdentityUnknown), Attention::ServerIdentityChanged);
        assert_eq!(Attention::for_error(ErrorName::NotFound), Attention::None);
    }

    #[test]
    fn values_for_the_c_abi() {
        use crate::ffi::Value as V;
        assert_eq!(Value::Invalid.to_ffi(), None);
        assert_eq!(Value::Map(vec![("a".into(), Value::Bool(true))]).to_ffi(), None);
        assert_eq!(Value::Bool(true).to_ffi(), Some(V::Bool(true)));
        assert_eq!(Value::Int(-3).to_ffi(), Some(V::Int(-3)));
        assert_eq!(Value::UInt(u32::MAX).to_ffi(), Some(V::Int(i64::from(u32::MAX))));
        assert_eq!(Value::LongLong(i64::MIN).to_ffi(), Some(V::Int(i64::MIN)));
        assert_eq!(Value::ULongLong(7).to_ffi(), Some(V::Int(7)));
        assert_eq!(Value::ULongLong(u64::MAX).to_ffi(), None);
        assert_eq!(Value::String("s".into()).to_ffi(), Some(V::Str("s".into())));
        assert_eq!(Value::StringList(vec!["a".into()]).to_ffi(), Some(V::StrList(vec!["a".into()])));
        assert_eq!(Value::ByteArray(b"x".to_vec()).to_ffi(), Some(V::Bytes(b"x".to_vec())));
    }

    #[test]
    fn params_for_the_c_abi() {
        crate::log::capture::start();
        let params = ConnectionParams {
            provider: "sftp".into(),
            host: "h".into(),
            port: 22,
            username: "u".into(),
            options: vec![
                ("host_key".into(), Value::String("pin".into())),
                ("nested".into(), Value::Map(Vec::new())),
            ],
            connect_timeout_ms: 1,
            request_timeout_ms: 2,
        };
        let ffi = params.to_ffi();
        assert_eq!(
            (ffi.provider.as_str(), ffi.host.as_str(), ffi.port, ffi.username.as_str()),
            ("sftp", "h", 22, "u")
        );
        assert_eq!((ffi.connect_timeout_ms, ffi.request_timeout_ms), (1, 2));
        assert_eq!(ffi.options.len(), 1);
        assert_eq!(ffi.options.get("host_key"), Some(&crate::ffi::Value::Str("pin".into())));
        let logged = crate::log::capture::take();
        assert_eq!(logged.len(), 1);
        assert!(logged[0].1.contains("nested"), "{logged:?}");
    }
}
