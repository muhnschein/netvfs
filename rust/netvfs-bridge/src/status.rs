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
mod tests {
    use super::*;

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
