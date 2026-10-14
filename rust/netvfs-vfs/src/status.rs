// SPDX-License-Identifier: LGPL-2.1-or-later
//! [`Status`]: a failure as netvfs reports it (XC-21, XC-24), from a backend
//! or from the bridge's own checks, and [`ErrorName`], its XC-21 name. The
//! bridge sends the name as the D-Bus error `org.netvfs.Error.<Name>`
//! (SPEC-v2 XB-9); the C ABIs carry it as text (`nvb_error.name`).

use std::fmt;

/// Prefix of the D-Bus error names (XB-9).
pub const ERROR_PREFIX: &str = "org.netvfs.Error.";

macro_rules! error_names {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// An XC-21 error name, in the order of `src/core/error.h`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorName {
            $($(#[$doc])* $name,)*
        }

        impl ErrorName {
            /// Every name, in the order of `src/core/error.h`.
            pub const ALL: [Self; error_names!(@count $($name)*)] = [$(Self::$name,)*];

            /// The bare name, as `errorName()` gives it.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$name => stringify!($name),)*
                }
            }

            /// The D-Bus error name, `org.netvfs.Error.<Name>`.
            #[must_use]
            pub const fn dbus_name(self) -> &'static str {
                match self {
                    $(Self::$name => concat!("org.netvfs.Error.", stringify!($name)),)*
                }
            }
        }
    };
    (@count) => { 0 };
    (@count $head:ident $($tail:ident)*) => { 1 + error_names!(@count $($tail)*) };
}

error_names! {
    /// The operation was canceled.
    Canceled,
    /// The server could not be reached.
    NetworkUnreachable,
    /// The server did not answer in time.
    Timeout,
    /// The server's identity is not known yet.
    ServerIdentityUnknown,
    /// The server's identity differs from the pinned one.
    ServerIdentityChanged,
    /// The credentials were refused.
    AuthFailed,
    /// A mandatory security requirement could not be met.
    SecurityPolicy,
    /// Not allowed (also: no consent, XB-6).
    PermissionDenied,
    /// No such file, location, handle, job or question.
    NotFound,
    /// The target exists.
    AlreadyExists,
    /// The server has no space left.
    NoSpace,
    /// The backend or server cannot do this.
    Unsupported,
    /// The server or client broke the protocol.
    ProtocolError,
    /// A bug or an unexpected state.
    Internal,
    /// An established connection dropped.
    ConnectionLost,
    /// A path component is not a folder.
    NotADirectory,
    /// The path is a folder.
    IsADirectory,
    /// The folder is not empty.
    DirectoryNotEmpty,
    /// The path or name is not valid.
    InvalidName,
    /// The file system is read-only.
    ReadOnlyFilesystem,
    /// The file is locked (SMB sharing violation).
    Locked,
    /// Too many connections, requests, handles or jobs.
    TooManyConnections,
    /// The server asks to slow down (with Retry-After).
    RateLimited,
}

impl ErrorName {
    /// The name for a bare name (`NotFound`), or `None` for an unknown one.
    #[must_use]
    pub fn parse(bare: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.as_str() == bare)
    }

    /// The name for a D-Bus error name (`org.netvfs.Error.NotFound`).
    #[must_use]
    pub fn from_dbus_name(name: &str) -> Option<Self> {
        name.strip_prefix(ERROR_PREFIX).and_then(Self::parse)
    }
}

impl fmt::Display for ErrorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

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

    /// A malformed call (`ProtocolError`; the bridge's dispatch replies
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

    /// The caller refuses (`PermissionDenied`).
    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorName::PermissionDenied, message)
    }

    /// An `Internal` status: a bug or an unexpected state.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorName::Internal, message)
    }

    /// `Canceled` (C-9), without a message.
    #[must_use]
    pub fn canceled() -> Self {
        Self::new(ErrorName::Canceled, "")
    }

    /// `Unsupported`: the backend cannot do this (XC-5).
    #[must_use]
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorName::Unsupported, message)
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

    // The 23 XC-21 names of src/core/error.cpp (all but `None`), in order.
    #[test]
    fn names_are_the_xc21_names() {
        let names: Vec<&str> = ErrorName::ALL.iter().map(|n| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "Canceled",
                "NetworkUnreachable",
                "Timeout",
                "ServerIdentityUnknown",
                "ServerIdentityChanged",
                "AuthFailed",
                "SecurityPolicy",
                "PermissionDenied",
                "NotFound",
                "AlreadyExists",
                "NoSpace",
                "Unsupported",
                "ProtocolError",
                "Internal",
                "ConnectionLost",
                "NotADirectory",
                "IsADirectory",
                "DirectoryNotEmpty",
                "InvalidName",
                "ReadOnlyFilesystem",
                "Locked",
                "TooManyConnections",
                "RateLimited",
            ]
        );
        for n in ErrorName::ALL {
            assert_eq!(ErrorName::parse(n.as_str()), Some(n));
            assert_eq!(ErrorName::from_dbus_name(n.dbus_name()), Some(n));
            assert_eq!(n.dbus_name(), format!("{ERROR_PREFIX}{n}"));
        }
        assert_eq!(ErrorName::parse("None"), None);
        assert_eq!(ErrorName::parse("notfound"), None);
        assert_eq!(ErrorName::from_dbus_name("NotFound"), None);
    }

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
        assert_eq!(Status::canceled(), Status::new(ErrorName::Canceled, ""));
        assert_eq!(Status::unsupported("no"), Status::new(ErrorName::Unsupported, "no"));
    }
}
