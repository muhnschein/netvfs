// SPDX-License-Identifier: LGPL-2.1-or-later
//! The error type of the fake's methods: D-Bus errors as the real bridge
//! sends them (`org.netvfs.Error.<Name>` with message and optional details,
//! or the standard `InvalidArgs`).

use super::tree::TreeError;
use crate::errors::{ERROR_PREFIX, ErrorName, INVALID_ARGS};
use std::collections::HashMap;
use zbus::DBusError;
use zbus::message::{Header, Message};
use zbus::zvariant::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    /// Full D-Bus error name.
    full: String,
    message: String,
    detail: Option<String>,
    retry_after_ms: Option<u64>,
}

impl Fail {
    /// `org.netvfs.Error.<name>`.
    pub fn net(name: ErrorName, message: &str) -> Self {
        Self::scripted(name.as_str(), message)
    }

    /// `org.netvfs.Error.<bare>` for a name a test scripted, which need not
    /// be one this crate knows.
    pub fn scripted(bare: &str, message: &str) -> Self {
        Self {
            full: format!("{ERROR_PREFIX}{bare}"),
            message: message.to_owned(),
            detail: None,
            retry_after_ms: None,
        }
    }

    /// `org.freedesktop.DBus.Error.InvalidArgs`.
    pub fn args(message: &str) -> Self {
        Self {
            full: INVALID_ARGS.to_owned(),
            message: message.to_owned(),
            detail: None,
            retry_after_ms: None,
        }
    }

    pub fn with_detail(mut self, detail: Option<String>, retry_after_ms: Option<u64>) -> Self {
        self.detail = detail;
        self.retry_after_ms = retry_after_ms;
        self
    }

    /// The bare XC-21 name, for `ListDone` and `JobFinished`.
    pub fn bare(&self) -> &str {
        self.full.strip_prefix(ERROR_PREFIX).unwrap_or(&self.full)
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// `JobFinished.extra` entries describing this error.
    pub fn extra(&self) -> HashMap<String, Value<'static>> {
        let mut extra = HashMap::new();
        if let Some(d) = &self.detail {
            extra.insert("detail".to_owned(), Value::from(d.clone()));
        }
        if let Some(r) = self.retry_after_ms {
            extra.insert("retryAfterMs".to_owned(), Value::from(i64::try_from(r).unwrap_or(i64::MAX)));
        }
        extra
    }
}

impl From<TreeError> for Fail {
    fn from(e: TreeError) -> Self {
        Self::net(e.name, &e.message)
    }
}

impl DBusError for Fail {
    fn create_reply(&self, msg: &Header<'_>) -> zbus::Result<Message> {
        let builder = Message::error(msg, self.name())?;
        let extra = self.extra();
        if extra.is_empty() {
            builder.build(&(self.message.as_str(),))
        } else {
            builder.build(&(self.message.as_str(), extra))
        }
    }

    fn name(&self) -> zbus::names::ErrorName<'_> {
        zbus::names::ErrorName::try_from(self.full.as_str()).unwrap_or_else(|_| {
            zbus::names::ErrorName::from_static_str_unchecked(ErrorName::Internal.dbus_name())
        })
    }

    fn description(&self) -> Option<&str> {
        Some(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_extra() {
        let f = Fail::net(ErrorName::Locked, "busy").with_detail(Some("d".into()), Some(250));
        assert_eq!(f.bare(), "Locked");
        assert_eq!(f.name().as_str(), "org.netvfs.Error.Locked");
        assert_eq!(f.message(), "busy");
        let extra = f.extra();
        assert_eq!(extra.len(), 2);
        assert_eq!(f.description(), Some("busy"));
        let a = Fail::args("bad");
        assert_eq!(a.bare(), "org.freedesktop.DBus.Error.InvalidArgs");
        assert!(a.extra().is_empty());
        assert_eq!(Fail::scripted("Odd", "x").name().as_str(), "org.netvfs.Error.Odd");
        let t: Fail = TreeError { name: ErrorName::NotFound, message: "x".into() }.into();
        assert_eq!(t.bare(), "NotFound");
    }
}
