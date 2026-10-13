// SPDX-License-Identifier: LGPL-2.1-or-later
//! The outcome of a failed operation: an XC-21 error name, a message, and the
//! XC-24 details (`detail`, `retryAfterMs`). The Rust form of the C++
//! `NetVfs::Result` with `error != None` (design §3.2 key types).

use netvfs_bridge_proto::ErrorName;
use std::fmt;

/// A failure: what `org.netvfs.Error.<name>` replies, `ListDone` and
/// `JobFinished` carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The XC-21 name.
    pub name: ErrorName,
    /// The human message; may be empty (error replies then carry the name).
    pub message: String,
    /// Protocol status for logs and a details view; empty when none.
    pub detail: String,
    /// When to try again, in ms; -1 when none.
    pub retry_after_ms: i64,
}

impl Status {
    /// A status with a name and a message, without details.
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
    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(ErrorName::ProtocolError, message)
    }

    /// An invalid path or name (`InvalidName`).
    pub fn invalid_name(message: impl Into<String>) -> Self {
        Self::new(ErrorName::InvalidName, message)
    }

    /// The bridge refuses (`PermissionDenied`).
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorName::PermissionDenied, message)
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
}
