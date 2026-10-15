// SPDX-License-Identifier: LGPL-2.1-or-later
//! The crate's error, and how it becomes a netvfs [`Status`] (SPEC-smb 5,
//! XC-21): the same failure means something else during sign-in than on an
//! established connection.

use std::fmt;

use netvfs_vfs::{ErrorName, Status};

use crate::status::{NtStatus, status_for, with_context};

/// "The server closed the connection" during sign-in.
pub const SERVER_CLOSED: &str =
    "the server closed the connection; it may not support SMB 3.1.1, signing or encryption";
/// A refusal during sign-in that is about neither the credentials nor the
/// share name.
pub const SESSION_REFUSED: &str = "the server refused the session; it may require a protocol version, cipher \
     or signing algorithm this device does not offer (SMB 3.1.1 with AES-GCM and AES-CMAC), or deny this \
     account the share";
/// ACCESS_DENIED at TREE_CONNECT: Samba gives it for an account that may not
/// use the share and for a share that needs encryption the session lacks.
pub const SHARE_REFUSED: &str = "the server refused the share: this account may not use it, or the server \
     and this device have no encryption cipher in common";
/// XC-21: an established connection dropped.
pub const CONNECTION_LOST: &str = "the connection to the server was lost";

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The server answered with an error status.
    Status(NtStatus),
    /// The server sent something malformed or out of protocol; the
    /// connection stays usable unless [`Error::Lost`] follows.
    Protocol(String),
    /// Refused on policy grounds: dialect, cipher, signing, guest mapping,
    /// a message that failed its integrity check during sign-in.
    Policy(String),
    /// The connection is gone; the text says why.
    Lost(String),
    /// The server could not be reached.
    Unreachable(String),
    /// A request or the connect did not finish in time.
    Timeout,
    /// The caller canceled.
    Canceled,
    /// A status decided here (names, ranges, local limits, callbacks).
    Local(Status),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(s) => write!(f, "NT status {s}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::Policy(m) => write!(f, "security policy: {m}"),
            Self::Lost(m) => write!(f, "connection lost: {m}"),
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
            Self::Timeout => f.write_str("the server did not answer in time"),
            Self::Canceled => f.write_str("canceled"),
            Self::Local(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Status> for Error {
    fn from(s: Status) -> Self {
        Self::Local(s)
    }
}

/// Shorthand.
pub type Result<T> = std::result::Result<T, Error>;

/// A protocol error.
pub(crate) fn protocol(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// A policy refusal.
pub(crate) fn policy(msg: impl Into<String>) -> Error {
    Error::Policy(msg.into())
}

/// Where a failure happened (SPEC-smb 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// NEGOTIATE, SESSION_SETUP, TREE_CONNECT.
    Setup,
    /// A request on an authenticated session.
    Established,
}

impl Error {
    /// The netvfs status of this failure of `context` (an operation name
    /// such as "stat", or empty) in `phase`.
    #[must_use]
    pub fn status(self, context: &str, phase: Phase) -> Status {
        match self {
            Self::Status(nt) => {
                let status = status_for(nt, context);
                // During sign-in, a refusal that is about neither the
                // credentials nor the share name means the server wants
                // something this client does not offer (M-T9, M-T14).
                let keeps = matches!(
                    status.name,
                    ErrorName::AuthFailed | ErrorName::NotFound | ErrorName::Timeout | ErrorName::Unsupported
                );
                if phase == Phase::Setup && !keeps {
                    let reason = if nt == NtStatus::ACCESS_DENIED { SHARE_REFUSED } else { SESSION_REFUSED };
                    return Status::new(
                        ErrorName::SecurityPolicy,
                        with_context(context, &format!("{reason} (NT status 0x{:08x})", nt.0)),
                    )
                    .with_detail(status.detail);
                }
                status
            }
            Self::Protocol(m) => {
                Status::new(ErrorName::ProtocolError, with_context(context, &m)).with_detail(m)
            }
            Self::Policy(m) => Status::new(ErrorName::SecurityPolicy, m),
            Self::Lost(m) => match phase {
                Phase::Setup => Status::new(ErrorName::SecurityPolicy, SERVER_CLOSED).with_detail(m),
                Phase::Established => Status::new(ErrorName::ConnectionLost, CONNECTION_LOST).with_detail(m),
            },
            Self::Unreachable(m) => {
                Status::new(ErrorName::NetworkUnreachable, with_context("Cannot connect to the server", &m))
            }
            Self::Timeout => {
                Status::new(ErrorName::Timeout, with_context(context, "the server did not answer in time"))
            }
            Self::Canceled => Status::canceled(),
            Self::Local(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_keep_their_meaning_once_established() {
        let s = Error::Status(NtStatus::ACCESS_DENIED).status("remove", Phase::Established);
        assert_eq!(s.name, ErrorName::PermissionDenied);
        assert_eq!(s.message, "remove: access denied (NT status 0xc0000022)");
        let s = Error::Status(NtStatus::INVALID_PARAMETER).status("stat", Phase::Established);
        assert_eq!(s.name, ErrorName::ProtocolError);
    }

    #[test]
    fn setup_refusals_are_policy_unless_about_credentials_or_names() {
        let s = Error::Status(NtStatus::ACCESS_DENIED).status("", Phase::Setup);
        assert_eq!(s.name, ErrorName::SecurityPolicy);
        assert_eq!(s.message, format!("{SHARE_REFUSED} (NT status 0xc0000022)"));
        assert_eq!(s.detail, "NT status 0xc0000022 (STATUS_ACCESS_DENIED)");
        let s = Error::Status(NtStatus::INVALID_PARAMETER).status("sign in", Phase::Setup);
        assert_eq!(s.name, ErrorName::SecurityPolicy);
        assert_eq!(s.message, format!("sign in: {SESSION_REFUSED} (NT status 0xc000000d)"));
        for (nt, name) in [
            (NtStatus::LOGON_FAILURE, ErrorName::AuthFailed),
            (NtStatus::BAD_NETWORK_NAME, ErrorName::NotFound),
            (NtStatus::IO_TIMEOUT, ErrorName::Timeout),
            (NtStatus::PATH_NOT_COVERED, ErrorName::Unsupported),
        ] {
            assert_eq!(Error::Status(nt).status("", Phase::Setup).name, name);
        }
    }

    #[test]
    fn transport_failures_by_phase() {
        let s = Error::Lost("reset".into()).status("stat", Phase::Established);
        assert_eq!(
            (s.name, s.message.as_str(), s.detail.as_str()),
            (ErrorName::ConnectionLost, CONNECTION_LOST, "reset")
        );
        let s = Error::Lost("eof".into()).status("", Phase::Setup);
        assert_eq!((s.name, s.message.as_str()), (ErrorName::SecurityPolicy, SERVER_CLOSED));
        let s = Error::Timeout.status("stat", Phase::Established);
        assert_eq!(
            (s.name, s.message.as_str()),
            (ErrorName::Timeout, "stat: the server did not answer in time")
        );
        let s = Error::Unreachable("Connection refused".into()).status("", Phase::Setup);
        assert_eq!(
            (s.name, s.message.as_str()),
            (ErrorName::NetworkUnreachable, "Cannot connect to the server: Connection refused")
        );
        assert_eq!(Error::Canceled.status("x", Phase::Setup), Status::canceled());
    }

    #[test]
    fn local_policy_and_protocol() {
        let local = Status::invalid_name("bad");
        assert_eq!(Error::from(local.clone()).status("x", Phase::Established), local);
        let s = Error::Policy("no".into()).status("x", Phase::Established);
        assert_eq!((s.name, s.message.as_str()), (ErrorName::SecurityPolicy, "no"));
        let s = protocol("short").status("list", Phase::Setup);
        assert_eq!(
            (s.name, s.message.as_str(), s.detail.as_str()),
            (ErrorName::ProtocolError, "list: short", "short")
        );
        assert_eq!(policy("p"), Error::Policy("p".into()));
    }

    #[test]
    fn display() {
        assert_eq!(
            Error::Status(NtStatus::LOGON_FAILURE).to_string(),
            "NT status 0xc000006d (STATUS_LOGON_FAILURE)"
        );
        assert_eq!(protocol("x").to_string(), "protocol error: x");
        assert_eq!(policy("x").to_string(), "security policy: x");
        assert_eq!(Error::Lost("x".into()).to_string(), "connection lost: x");
        assert_eq!(Error::Unreachable("x".into()).to_string(), "unreachable: x");
        assert_eq!(Error::Timeout.to_string(), "the server did not answer in time");
        assert_eq!(Error::Canceled.to_string(), "canceled");
        assert_eq!(Error::Local(Status::internal("bug")).to_string(), "Internal: bug");
    }
}
