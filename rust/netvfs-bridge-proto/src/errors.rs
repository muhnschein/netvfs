// SPDX-License-Identifier: LGPL-2.1-or-later
//! Bridge errors: `org.netvfs.Error.<Name>` D-Bus errors with the message as
//! first argument and an optional `a{sv}` (`detail`, `retryAfterMs`) as second
//! (SPEC-v2 XB-9, XC-24). The names are the XC-21 names of `src/core/error.h`.

use crate::wire::{value_i64, value_str};
use std::collections::HashMap;
use std::fmt;
use zbus::DBusError as _;
use zbus::zvariant::OwnedValue;

pub use netvfs_vfs::status::{ERROR_PREFIX, ErrorName};

/// A malformed call (wrong signature, count, type or range).
pub const INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";
/// A call of a method the bridge does not have.
pub const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";

/// Failure of a bridge call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// A backend or policy error from the bridge (`org.netvfs.Error.*`).
    Remote {
        /// Full D-Bus error name.
        name: String,
        /// The human message.
        message: String,
        /// Protocol status for logs and a details view (XC-24).
        detail: Option<String>,
        /// When to try again (`RateLimited`, `TooManyConnections`).
        retry_after_ms: Option<u64>,
    },
    /// The bridge refused the arguments (malformed call).
    InvalidArgs(String),
    /// The bridge has no such method.
    UnknownMethod(String),
    /// The socket is gone or the connection broke.
    Disconnected(String),
    /// The bridge sent something this client cannot decode.
    Protocol(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote { name, message, .. } => write!(f, "{name}: {message}"),
            Self::InvalidArgs(m) => write!(f, "invalid arguments: {m}"),
            Self::UnknownMethod(m) => write!(f, "unknown method: {m}"),
            Self::Disconnected(m) => write!(f, "connection lost: {m}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl BridgeError {
    /// A `Remote` error with just a name and message.
    #[must_use]
    pub fn remote(name: ErrorName, message: &str) -> Self {
        Self::Remote {
            name: name.dbus_name().to_owned(),
            message: message.to_owned(),
            detail: None,
            retry_after_ms: None,
        }
    }

    /// The bare XC-21 name (`NotFound`, …) of a netvfs error, also of one
    /// this client does not know yet.
    #[must_use]
    pub fn netvfs_name(&self) -> Option<&str> {
        match self {
            Self::Remote { name, .. } => name.strip_prefix(ERROR_PREFIX),
            _ => None,
        }
    }

    /// The XC-21 name of a netvfs error this client knows.
    #[must_use]
    pub fn error_name(&self) -> Option<ErrorName> {
        self.netvfs_name().and_then(ErrorName::parse)
    }

    /// The full D-Bus error name: `org.netvfs.Error.<Name>`, [`INVALID_ARGS`]
    /// or [`UNKNOWN_METHOD`]; `None` for a failure that was no error reply.
    #[must_use]
    pub fn dbus_name(&self) -> Option<&str> {
        match self {
            Self::Remote { name, .. } => Some(name),
            Self::InvalidArgs(_) => Some(INVALID_ARGS),
            Self::UnknownMethod(_) => Some(UNKNOWN_METHOD),
            Self::Disconnected(_) | Self::Protocol(_) => None,
        }
    }

    /// Builds the error of `ListDone` / `JobFinished`, where the error is a
    /// bare name and an empty name means success.
    #[must_use]
    pub fn from_bare(name: &str, message: &str, extra: &HashMap<String, OwnedValue>) -> Option<Self> {
        if name.is_empty() {
            return None;
        }
        Some(Self::Remote {
            name: format!("{ERROR_PREFIX}{name}"),
            message: message.to_owned(),
            detail: extra.get("detail").and_then(|v| value_str(v)),
            retry_after_ms: extra
                .get("retryAfterMs")
                .and_then(|v| value_i64(v))
                .and_then(|n| u64::try_from(n).ok()),
        })
    }

    fn from_method_error(name: &str, desc: Option<String>, extra: &HashMap<String, OwnedValue>) -> Self {
        let message = desc.unwrap_or_default();
        match name {
            INVALID_ARGS => Self::InvalidArgs(message),
            UNKNOWN_METHOD => Self::UnknownMethod(message),
            "" => Self::Protocol("error without a name".to_owned()),
            _ => {
                let mut e = Self::from_bare(name, &message, extra)
                    .unwrap_or_else(|| Self::Protocol("error without a name".to_owned()));
                // from_bare prefixed the name; keep the name as it came.
                if let Self::Remote { name: n, .. } = &mut e {
                    name.clone_into(n);
                }
                e
            }
        }
    }
}

impl From<zbus::Error> for BridgeError {
    fn from(err: zbus::Error) -> Self {
        match err {
            zbus::Error::MethodError(name, desc, msg) => {
                let extra = msg
                    .body()
                    .deserialize_unchecked::<(String, HashMap<String, OwnedValue>)>()
                    .map(|(_, extra)| extra)
                    .unwrap_or_default();
                Self::from_method_error(name.as_str(), desc, &extra)
            }
            zbus::Error::FDO(e) => {
                let desc = e.description().map(str::to_owned);
                Self::from_method_error(e.name().as_str(), desc, &HashMap::new())
            }
            zbus::Error::Variant(_) | zbus::Error::InvalidReply | zbus::Error::ExcessData => {
                Self::Protocol(err.to_string())
            }
            other => Self::Disconnected(other.to_string()),
        }
    }
}

impl From<std::io::Error> for BridgeError {
    fn from(err: std::io::Error) -> Self {
        Self::Disconnected(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Value;

    fn extra(pairs: Vec<(&str, Value<'static>)>) -> HashMap<String, OwnedValue> {
        pairs.into_iter().map(|(k, v)| (k.to_owned(), OwnedValue::try_from(v).unwrap())).collect()
    }

    #[test]
    fn bare_names_with_detail_and_retry() {
        assert_eq!(BridgeError::from_bare("", "", &HashMap::new()), None);
        let e = BridgeError::from_bare(
            "RateLimited",
            "slow down",
            &extra(vec![("detail", Value::from("429")), ("retryAfterMs", Value::from(1500i64))]),
        )
        .unwrap();
        assert_eq!(e.netvfs_name(), Some("RateLimited"));
        assert_eq!(e.error_name(), Some(ErrorName::RateLimited));
        assert_eq!(e.dbus_name(), Some("org.netvfs.Error.RateLimited"));
        match e {
            BridgeError::Remote { name, message, detail, retry_after_ms } => {
                assert_eq!(name, "org.netvfs.Error.RateLimited");
                assert_eq!(message, "slow down");
                assert_eq!(detail.as_deref(), Some("429"));
                assert_eq!(retry_after_ms, Some(1500));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn negative_retry_is_ignored() {
        let e =
            BridgeError::from_bare("Locked", "", &extra(vec![("retryAfterMs", Value::from(-1i64))])).unwrap();
        assert!(matches!(e, BridgeError::Remote { retry_after_ms: None, .. }));
    }

    #[test]
    fn method_error_names() {
        let none = HashMap::new();
        assert_eq!(
            BridgeError::from_method_error(INVALID_ARGS, Some("x".into()), &none),
            BridgeError::InvalidArgs("x".into())
        );
        assert_eq!(
            BridgeError::from_method_error(UNKNOWN_METHOD, None, &none),
            BridgeError::UnknownMethod(String::new())
        );
        let e = BridgeError::from_method_error("org.netvfs.Error.NotFound", Some("gone".into()), &none);
        assert_eq!(e.netvfs_name(), Some("NotFound"));
        assert_eq!(e.to_string(), "org.netvfs.Error.NotFound: gone");
        let other = BridgeError::from_method_error("org.example.Odd", None, &none);
        assert_eq!(other.netvfs_name(), None);
        assert_eq!(other.dbus_name(), Some("org.example.Odd"));
        let newer = BridgeError::from_method_error("org.netvfs.Error.FromTheFuture", None, &none);
        assert_eq!((newer.netvfs_name(), newer.error_name()), (Some("FromTheFuture"), None));
        assert!(matches!(BridgeError::from_method_error("", None, &none), BridgeError::Protocol(_)));
        assert_eq!(
            BridgeError::remote(ErrorName::Locked, "busy").to_string(),
            "org.netvfs.Error.Locked: busy"
        );
    }

    #[test]
    fn io_errors_are_disconnects() {
        let e = BridgeError::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert!(matches!(e, BridgeError::Disconnected(_)));
        assert_eq!(e.dbus_name(), None);
        assert!(e.to_string().starts_with("connection lost: "));
        let e = BridgeError::from(zbus::Error::Unsupported);
        assert!(matches!(e, BridgeError::Disconnected(_)));
        let e = BridgeError::from(zbus::Error::InvalidReply);
        assert!(matches!(e, BridgeError::Protocol(_)));
        assert!(e.to_string().starts_with("protocol error: "));
        let e: &dyn std::error::Error = &e;
        assert!(e.source().is_none());
    }
}
