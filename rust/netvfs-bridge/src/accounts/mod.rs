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
    }
}
