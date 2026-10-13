// SPDX-License-Identifier: LGPL-2.1-or-later
//! `Status`: a failed `NetVfs::Result` (XC-21 name, message), as the bridge
//! reports it to consumers and in its log.

use netvfs_bridge_proto::ErrorName;
use std::fmt;

/// A failure: an XC-21 error name with its message, `detail` and
/// `retryAfterMs` (XC-24; `-1`: none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The XC-21 name.
    pub name: ErrorName,
    /// Human-readable, may be empty.
    pub message: String,
    /// Server text, may be empty.
    pub detail: String,
    /// Milliseconds to wait before retrying, `-1` for none.
    pub retry_after_ms: i64,
}

impl Status {
    /// A failure with a message, without detail or retry hint.
    #[must_use]
    pub fn new(name: ErrorName, message: impl Into<String>) -> Self {
        Self { name, message: message.into(), detail: String::new(), retry_after_ms: -1 }
    }
}

/// `Result::toString()`: the name, then `": "` and the message if there is
/// one.
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            f.write_str(self.name.as_str())
        } else {
            write!(f, "{}: {}", self.name, self.message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_follows_result_to_string() {
        assert_eq!(Status::new(ErrorName::NotFound, "").to_string(), "NotFound");
        assert_eq!(Status::new(ErrorName::Timeout, "slow").to_string(), "Timeout: slow");
        let s = Status::new(ErrorName::Internal, "x");
        assert_eq!((s.detail.as_str(), s.retry_after_ms), ("", -1));
    }
}
