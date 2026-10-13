// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Status`]: a failure as the bridge reports it (XC-21, XC-24), whether it
//! came from a backend through the C ABI or from the bridge's own checks.

use netvfs_bridge_proto::ErrorName;
use std::fmt;

/// A failed operation: an XC-21 name, a human message, a protocol detail
/// for logs (XC-24) and, for `RateLimited` and `TooManyConnections`, when to
/// try again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The XC-21 name.
    pub name: ErrorName,
    /// UTF-8, may be empty.
    pub message: String,
    /// UTF-8, may be empty.
    pub detail: String,
    /// Milliseconds; -1: none.
    pub retry_after_ms: i64,
}

impl Status {
    /// A status with a name and a message, no detail and no retry time.
    #[must_use]
    pub fn new(name: ErrorName, message: impl Into<String>) -> Self {
        Self { name, message: message.into(), detail: String::new(), retry_after_ms: -1 }
    }

    /// The same status with `detail` set.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// The same status with `retryAfterMs` set.
    #[must_use]
    pub const fn with_retry_after_ms(mut self, ms: i64) -> Self {
        self.retry_after_ms = ms;
        self
    }

    /// A malformed call (`ProtocolError`; the dispatch replies
    /// `org.freedesktop.DBus.Error.InvalidArgs` for it, XSEC-7).
    #[must_use]
    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(ErrorName::ProtocolError, message)
    }

    /// An invalid path or name (`InvalidName`).
    #[must_use]
    pub fn invalid_name(message: impl Into<String>) -> Self {
        Self::new(ErrorName::InvalidName, message)
    }

    /// The bridge refuses (`PermissionDenied`).
    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorName::PermissionDenied, message)
    }

    /// An `Internal` status: a bug or an unexpected state.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorName::Internal, message)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            f.write_str(self.name.as_str())
        } else {
            write!(f, "{}: {}", self.name, self.message)
        }
    }
}

impl std::error::Error for Status {}

#[cfg(test)]
#[allow(clippy::assertions_on_result_states, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn builders_and_display() {
        let s = Status::new(ErrorName::RateLimited, "slow").with_detail("429").with_retry_after_ms(1500);
        assert_eq!(s.name, ErrorName::RateLimited);
        assert_eq!((s.message.as_str(), s.detail.as_str(), s.retry_after_ms), ("slow", "429", 1500));
        assert_eq!(s.to_string(), "RateLimited: slow");
        assert_eq!(Status::new(ErrorName::Locked, "").to_string(), "Locked");
        assert_eq!(Status::new(ErrorName::Locked, "").retry_after_ms, -1);
        assert_eq!(Status::invalid_args("x").name, ErrorName::ProtocolError);
        assert_eq!(Status::invalid_name("x").name, ErrorName::InvalidName);
        assert_eq!(Status::permission_denied("x").name, ErrorName::PermissionDenied);
    }

    #[test]
    fn constructors_and_display() {
        let s = Status::new(ErrorName::NotFound, "gone");
        assert_eq!((s.detail.as_str(), s.retry_after_ms), ("", -1));
        assert_eq!(s.to_string(), "NotFound: gone");
        assert_eq!(Status::new(ErrorName::Canceled, "").to_string(), "Canceled");
        let i = Status::internal("bug");
        assert_eq!((i.name, i.message.as_str()), (ErrorName::Internal, "bug"));
        let e: &dyn std::error::Error = &i;
        assert!(e.source().is_none());
    }
}
