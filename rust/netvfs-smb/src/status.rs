// SPDX-License-Identifier: LGPL-2.1-or-later
//! NT status codes (MS-ERREF 2.3) and their mapping to netvfs errors
//! (SPEC-smb §5, SPEC-v2 XC-21, XM-9).

use std::fmt;

use netvfs_vfs::{ErrorName, Status};

/// An NT status value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

macro_rules! statuses {
    ($($(#[$doc:meta])* $name:ident = $value:literal,)*) => {
        impl NtStatus {
            $($(#[$doc])* pub const $name: Self = Self($value);)*

            /// The `STATUS_*` name, for a known status.
            #[must_use]
            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some(concat!("STATUS_", stringify!($name))),)*
                    _ => None,
                }
            }
        }
    };
}

statuses! {
    /// STATUS_SUCCESS.
    SUCCESS = 0x0000_0000,
    /// STATUS_PENDING (interim responses).
    PENDING = 0x0000_0103,
    /// STATUS_BUFFER_OVERFLOW (more data: a pipe read or an IOCTL).
    BUFFER_OVERFLOW = 0x8000_0005,
    /// STATUS_NO_MORE_FILES.
    NO_MORE_FILES = 0x8000_0006,
    /// STATUS_INVALID_PARAMETER.
    INVALID_PARAMETER = 0xC000_000D,
    /// STATUS_NO_SUCH_FILE.
    NO_SUCH_FILE = 0xC000_000F,
    /// STATUS_END_OF_FILE.
    END_OF_FILE = 0xC000_0011,
    /// STATUS_MORE_PROCESSING_REQUIRED.
    MORE_PROCESSING_REQUIRED = 0xC000_0016,
    /// STATUS_ACCESS_DENIED.
    ACCESS_DENIED = 0xC000_0022,
    /// STATUS_OBJECT_NAME_INVALID.
    OBJECT_NAME_INVALID = 0xC000_0033,
    /// STATUS_OBJECT_NAME_NOT_FOUND.
    OBJECT_NAME_NOT_FOUND = 0xC000_0034,
    /// STATUS_OBJECT_NAME_COLLISION.
    OBJECT_NAME_COLLISION = 0xC000_0035,
    /// STATUS_OBJECT_PATH_NOT_FOUND.
    OBJECT_PATH_NOT_FOUND = 0xC000_003A,
    /// STATUS_SHARING_VIOLATION.
    SHARING_VIOLATION = 0xC000_0043,
    /// STATUS_DELETE_PENDING.
    DELETE_PENDING = 0xC000_0056,
    /// STATUS_NO_SUCH_USER.
    NO_SUCH_USER = 0xC000_0064,
    /// STATUS_WRONG_PASSWORD.
    WRONG_PASSWORD = 0xC000_006A,
    /// STATUS_LOGON_FAILURE.
    LOGON_FAILURE = 0xC000_006D,
    /// STATUS_ACCOUNT_RESTRICTION.
    ACCOUNT_RESTRICTION = 0xC000_006E,
    /// STATUS_INVALID_LOGON_HOURS.
    INVALID_LOGON_HOURS = 0xC000_006F,
    /// STATUS_PASSWORD_EXPIRED.
    PASSWORD_EXPIRED = 0xC000_0071,
    /// STATUS_ACCOUNT_DISABLED.
    ACCOUNT_DISABLED = 0xC000_0072,
    /// STATUS_DISK_FULL.
    DISK_FULL = 0xC000_007F,
    /// STATUS_INSUFFICIENT_RESOURCES.
    INSUFFICIENT_RESOURCES = 0xC000_009A,
    /// STATUS_FILE_IS_A_DIRECTORY.
    FILE_IS_A_DIRECTORY = 0xC000_00BA,
    /// STATUS_NOT_SUPPORTED.
    NOT_SUPPORTED = 0xC000_00BB,
    /// STATUS_NETWORK_NAME_DELETED.
    NETWORK_NAME_DELETED = 0xC000_00C9,
    /// STATUS_BAD_NETWORK_NAME.
    BAD_NETWORK_NAME = 0xC000_00CC,
    /// STATUS_REQUEST_NOT_ACCEPTED.
    REQUEST_NOT_ACCEPTED = 0xC000_00D0,
    /// STATUS_IO_TIMEOUT.
    IO_TIMEOUT = 0xC000_00B5,
    /// STATUS_DIRECTORY_NOT_EMPTY.
    DIRECTORY_NOT_EMPTY = 0xC000_0101,
    /// STATUS_NOT_A_DIRECTORY.
    NOT_A_DIRECTORY = 0xC000_0103,
    /// STATUS_CANCELLED.
    CANCELLED = 0xC000_0120,
    /// STATUS_FILE_CLOSED.
    FILE_CLOSED = 0xC000_0128,
    /// STATUS_ACCOUNT_EXPIRED.
    ACCOUNT_EXPIRED = 0xC000_0193,
    /// STATUS_USER_SESSION_DELETED.
    USER_SESSION_DELETED = 0xC000_0203,
    /// STATUS_PASSWORD_MUST_CHANGE.
    PASSWORD_MUST_CHANGE = 0xC000_0224,
    /// STATUS_ACCOUNT_LOCKED_OUT.
    ACCOUNT_LOCKED_OUT = 0xC000_0234,
    /// STATUS_PATH_NOT_COVERED (a DFS link).
    PATH_NOT_COVERED = 0xC000_0257,
    /// STATUS_DFS_UNAVAILABLE.
    DFS_UNAVAILABLE = 0xC000_026D,
    /// STATUS_NETWORK_SESSION_EXPIRED.
    NETWORK_SESSION_EXPIRED = 0xC000_035C,
    /// STATUS_QUOTA_EXCEEDED.
    QUOTA_EXCEEDED = 0xC000_0044,
}

impl NtStatus {
    /// Severity "error" (the two top bits are 11).
    #[must_use]
    pub fn is_error(self) -> bool {
        self.0 >> 30 == 3
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x} ({})", self.0, self.name().unwrap_or("Unknown"))
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The detail of XM-9.
pub const DFS_DETAIL: &str = "DFS referral";

/// SPEC-smb 5: the statuses with a netvfs error of their own, and the text
/// that names them. Any other status is `ProtocolError`.
const TABLE: [(NtStatus, ErrorName, &str); 22] = [
    (NtStatus::LOGON_FAILURE, ErrorName::AuthFailed, "the server rejected the user name or password"),
    (NtStatus::WRONG_PASSWORD, ErrorName::AuthFailed, "the server rejected the password"),
    (NtStatus::NO_SUCH_USER, ErrorName::AuthFailed, "the server does not know this user"),
    (NtStatus::ACCOUNT_DISABLED, ErrorName::AuthFailed, "the account is disabled"),
    (NtStatus::ACCOUNT_LOCKED_OUT, ErrorName::AuthFailed, "the account is locked"),
    (NtStatus::ACCOUNT_EXPIRED, ErrorName::AuthFailed, "the account has expired"),
    (NtStatus::ACCOUNT_RESTRICTION, ErrorName::AuthFailed, "the account may not sign in"),
    (NtStatus::INVALID_LOGON_HOURS, ErrorName::AuthFailed, "the account may not sign in at this time"),
    (NtStatus::PASSWORD_EXPIRED, ErrorName::AuthFailed, "the password has expired"),
    (NtStatus::PASSWORD_MUST_CHANGE, ErrorName::AuthFailed, "the password must be changed"),
    (NtStatus::BAD_NETWORK_NAME, ErrorName::NotFound, "share not found"),
    (NtStatus::ACCESS_DENIED, ErrorName::PermissionDenied, "access denied"),
    (NtStatus::OBJECT_NAME_NOT_FOUND, ErrorName::NotFound, "no such file or folder"),
    (NtStatus::OBJECT_PATH_NOT_FOUND, ErrorName::NotFound, "no such folder"),
    (NtStatus::OBJECT_NAME_COLLISION, ErrorName::AlreadyExists, "the name already exists"),
    (NtStatus::DISK_FULL, ErrorName::NoSpace, "the share is full"),
    (NtStatus::QUOTA_EXCEEDED, ErrorName::NoSpace, "the quota is exceeded"),
    (NtStatus::IO_TIMEOUT, ErrorName::Timeout, "the server did not answer in time"),
    // SPEC-v2 XC-9, XC-21
    (NtStatus::FILE_IS_A_DIRECTORY, ErrorName::IsADirectory, "this is a folder"),
    (NtStatus::NOT_A_DIRECTORY, ErrorName::NotADirectory, "this is not a folder"),
    (NtStatus::DIRECTORY_NOT_EMPTY, ErrorName::DirectoryNotEmpty, "the folder is not empty"),
    (NtStatus::SHARING_VIOLATION, ErrorName::Locked, "the file is in use"),
];

/// `context: message`, or the message alone without a context.
#[must_use]
pub fn with_context(context: &str, message: &str) -> String {
    if context.is_empty() { message.to_owned() } else { format!("{context}: {message}") }
}

/// The netvfs status for an NT status the server answered `context` with
/// (SPEC-smb 5): the table's error and text with the status in hex, DFS
/// statuses as `Unsupported` (XM-9), anything else `ProtocolError`. The
/// detail always names the status (XC-24).
#[must_use]
pub fn status_for(nt: NtStatus, context: &str) -> Status {
    if nt == NtStatus::PATH_NOT_COVERED || nt == NtStatus::DFS_UNAVAILABLE {
        return Status::unsupported(with_context(
            context,
            "the path is a DFS link to another server, which is not supported",
        ))
        .with_detail(DFS_DETAIL);
    }
    let detail = format!("NT status {nt}");
    match TABLE.iter().find(|(s, _, _)| *s == nt) {
        Some((_, name, text)) => {
            Status::new(*name, with_context(context, &format!("{text} (NT status 0x{:08x})", nt.0)))
                .with_detail(detail)
        }
        None => Status::new(ErrorName::ProtocolError, with_context(context, &detail)).with_detail(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_names_and_display() {
        assert!(NtStatus::LOGON_FAILURE.is_error());
        assert!(NtStatus(0xC000_0000).is_error());
        assert!(!NtStatus::NO_MORE_FILES.is_error());
        assert!(!NtStatus(0x4000_0000).is_error());
        assert!(!NtStatus::PENDING.is_error());
        assert_eq!(NtStatus::LOGON_FAILURE.to_string(), "0xc000006d (STATUS_LOGON_FAILURE)");
        assert_eq!(format!("{:?}", NtStatus(0xC000_0001)), "0xc0000001 (Unknown)");
        assert_eq!(NtStatus::DFS_UNAVAILABLE.name(), Some("STATUS_DFS_UNAVAILABLE"));
        assert_eq!(NtStatus(1).name(), None);
    }

    #[test]
    fn the_table_is_spec_smb_5() {
        let cases = [
            (NtStatus::LOGON_FAILURE, ErrorName::AuthFailed),
            (NtStatus::WRONG_PASSWORD, ErrorName::AuthFailed),
            (NtStatus::NO_SUCH_USER, ErrorName::AuthFailed),
            (NtStatus::ACCOUNT_DISABLED, ErrorName::AuthFailed),
            (NtStatus::ACCOUNT_LOCKED_OUT, ErrorName::AuthFailed),
            (NtStatus::ACCOUNT_EXPIRED, ErrorName::AuthFailed),
            (NtStatus::ACCOUNT_RESTRICTION, ErrorName::AuthFailed),
            (NtStatus::INVALID_LOGON_HOURS, ErrorName::AuthFailed),
            (NtStatus::PASSWORD_EXPIRED, ErrorName::AuthFailed),
            (NtStatus::PASSWORD_MUST_CHANGE, ErrorName::AuthFailed),
            (NtStatus::BAD_NETWORK_NAME, ErrorName::NotFound),
            (NtStatus::ACCESS_DENIED, ErrorName::PermissionDenied),
            (NtStatus::OBJECT_NAME_NOT_FOUND, ErrorName::NotFound),
            (NtStatus::OBJECT_PATH_NOT_FOUND, ErrorName::NotFound),
            (NtStatus::OBJECT_NAME_COLLISION, ErrorName::AlreadyExists),
            (NtStatus::DISK_FULL, ErrorName::NoSpace),
            (NtStatus::QUOTA_EXCEEDED, ErrorName::NoSpace),
            (NtStatus::IO_TIMEOUT, ErrorName::Timeout),
            (NtStatus::FILE_IS_A_DIRECTORY, ErrorName::IsADirectory),
            (NtStatus::NOT_A_DIRECTORY, ErrorName::NotADirectory),
            (NtStatus::DIRECTORY_NOT_EMPTY, ErrorName::DirectoryNotEmpty),
            (NtStatus::SHARING_VIOLATION, ErrorName::Locked),
            (NtStatus::PATH_NOT_COVERED, ErrorName::Unsupported),
            (NtStatus::DFS_UNAVAILABLE, ErrorName::Unsupported),
            (NtStatus::INVALID_PARAMETER, ErrorName::ProtocolError),
            (NtStatus(0xC0FF_EE00), ErrorName::ProtocolError),
        ];
        for (nt, name) in cases {
            assert_eq!(status_for(nt, "x").name, name, "{nt}");
        }
    }

    #[test]
    fn messages_and_details() {
        let s = status_for(NtStatus::LOGON_FAILURE, "sign in");
        assert_eq!(
            s.message,
            "sign in: the server rejected the user name or password (NT status 0xc000006d)"
        );
        assert_eq!(s.detail, "NT status 0xc000006d (STATUS_LOGON_FAILURE)");
        let s = status_for(NtStatus::BAD_NETWORK_NAME, "");
        assert_eq!(s.message, "share not found (NT status 0xc00000cc)");
        let s = status_for(NtStatus(0xC000_0001), "stat");
        assert_eq!(s.message, "stat: NT status 0xc0000001 (Unknown)");
        assert_eq!(s.detail, "NT status 0xc0000001 (Unknown)");
        let s = status_for(NtStatus::PATH_NOT_COVERED, "list");
        assert_eq!(s.message, "list: the path is a DFS link to another server, which is not supported");
        assert_eq!(s.detail, DFS_DETAIL);
        assert_eq!(with_context("", "m"), "m");
        assert_eq!(with_context("c", "m"), "c: m");
    }
}
