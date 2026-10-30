// SPDX-License-Identifier: LGPL-2.1-or-later
//! A failed request ([`Failure`]) and its [`Status`]: server `SSH_FX_*` codes by name, local failures (cancel,
//! timeout, lost or broken connection) as they are.

use crate::proto::{
    FX_BAD_MESSAGE, FX_CONNECTION_LOST, FX_EOF, FX_FAILURE, FX_FILE_ALREADY_EXISTS, FX_NO_CONNECTION,
    FX_NO_SUCH_FILE, FX_NO_SUCH_PATH, FX_OP_UNSUPPORTED, FX_PERMISSION_DENIED, FX_WRITE_PROTECT, StatusReply,
};
use crate::wire::WireError;
use netvfs_vfs::{ErrorName, Status};

/// A request that did not get the reply it wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The server answered with this status.
    Server(StatusReply),
    /// No usable answer: canceled, timed out, connection lost or broken.
    Local(Status),
}

impl From<Status> for Failure {
    fn from(s: Status) -> Self {
        Self::Local(s)
    }
}

impl Failure {
    /// The server's status code, if it answered.
    #[must_use]
    pub const fn code(&self) -> Option<u32> {
        match self {
            Self::Server(s) => Some(s.code),
            Self::Local(_) => None,
        }
    }

    /// The status for the caller; `context` names the path or "read".
    #[must_use]
    pub fn status(&self, context: &str) -> Status {
        match self {
            Self::Local(s) => s.clone(),
            Self::Server(reply) => server_status(reply, context),
        }
    }
}

fn server_status(reply: &StatusReply, context: &str) -> Status {
    let simple = |name, what: &str| Status::new(name, format!("{context}: {what}"));
    match reply.code {
        FX_NO_SUCH_FILE | FX_NO_SUCH_PATH => simple(ErrorName::NotFound, "not found"),
        FX_PERMISSION_DENIED | FX_WRITE_PROTECT => simple(ErrorName::PermissionDenied, "permission denied"),
        FX_FILE_ALREADY_EXISTS => simple(ErrorName::AlreadyExists, "already exists"),
        FX_OP_UNSUPPORTED => simple(ErrorName::Unsupported, "not supported by the server"),
        FX_NO_CONNECTION | FX_CONNECTION_LOST => simple(ErrorName::ConnectionLost, &message(reply)),
        _ => simple(ErrorName::ProtocolError, &message(reply)),
    }
}

fn message(reply: &StatusReply) -> String {
    if !reply.message.is_empty() {
        return reply.message.clone();
    }
    match reply.code {
        FX_EOF => "end of file".to_owned(),
        FX_FAILURE => "the server reported a failure".to_owned(),
        FX_BAD_MESSAGE => "the server did not understand the request".to_owned(),
        FX_NO_CONNECTION | FX_CONNECTION_LOST => "the server lost its connection".to_owned(),
        code => format!("the server reported error {code}"),
    }
}

/// `ConnectionLost`: SFTP channel or SSH connection went away.
#[must_use]
pub fn connection_lost() -> Status {
    Status::new(ErrorName::ConnectionLost, "The connection to the server was lost")
}

/// `ConnectionLost` after `disconnect`.
#[must_use]
pub fn connection_closed() -> Status {
    Status::new(ErrorName::ConnectionLost, "The connection was closed")
}

/// `ProtocolError`: unreadable reply.
#[must_use]
pub fn malformed(e: WireError) -> Status {
    Status::new(ErrorName::ProtocolError, "The server sent a malformed reply").with_detail(e.0)
}

/// `ProtocolError`: reply of the wrong kind.
#[must_use]
pub fn unexpected() -> Failure {
    Failure::Local(Status::new(ErrorName::ProtocolError, "The server sent an unexpected reply"))
}

/// `Timeout`.
#[must_use]
pub fn timed_out(ms: u128) -> Status {
    Status::new(ErrorName::Timeout, format!("The server did not answer within {} s", ms.div_ceil(1000)))
}

/// `Internal`: impossible range.
#[must_use]
pub fn invalid_range() -> Status {
    Status::internal("Invalid range")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(code: u32, message: &str) -> Failure {
        Failure::Server(StatusReply { code, message: message.to_owned() })
    }

    #[test]
    fn codes_map_to_names_with_the_context() {
        let cases = [
            (FX_NO_SUCH_FILE, "x", ErrorName::NotFound, "/a: not found"),
            (FX_NO_SUCH_PATH, "x", ErrorName::NotFound, "/a: not found"),
            (FX_PERMISSION_DENIED, "x", ErrorName::PermissionDenied, "/a: permission denied"),
            (FX_WRITE_PROTECT, "x", ErrorName::PermissionDenied, "/a: permission denied"),
            (FX_FILE_ALREADY_EXISTS, "x", ErrorName::AlreadyExists, "/a: already exists"),
            (FX_OP_UNSUPPORTED, "x", ErrorName::Unsupported, "/a: not supported by the server"),
            (FX_NO_CONNECTION, "gone", ErrorName::ConnectionLost, "/a: gone"),
            (FX_CONNECTION_LOST, "", ErrorName::ConnectionLost, "/a: the server lost its connection"),
            (FX_FAILURE, "Failure", ErrorName::ProtocolError, "/a: Failure"),
            (FX_FAILURE, "", ErrorName::ProtocolError, "/a: the server reported a failure"),
            (FX_BAD_MESSAGE, "", ErrorName::ProtocolError, "/a: the server did not understand the request"),
            (FX_EOF, "", ErrorName::ProtocolError, "/a: end of file"),
            (99, "", ErrorName::ProtocolError, "/a: the server reported error 99"),
            (99, "odd", ErrorName::ProtocolError, "/a: odd"),
        ];
        for (code, text, name, expected) in cases {
            let f = server(code, text);
            assert_eq!(f.code(), Some(code));
            let s = f.status("/a");
            assert_eq!((s.name, s.message.as_str()), (name, expected), "{code} {text}");
        }
    }

    #[test]
    fn local_failures_pass_through() {
        let f = Failure::from(Status::canceled());
        assert_eq!(f.code(), None);
        assert_eq!(f.status("/a"), Status::canceled());
        assert_eq!(unexpected().status("x").name, ErrorName::ProtocolError);
        assert_eq!(timed_out(3000).message, "The server did not answer within 3 s");
        assert_eq!(timed_out(2500).message, "The server did not answer within 3 s");
        assert_eq!(malformed(WireError("short")).detail, "short");
        assert_eq!(connection_lost().name, ErrorName::ConnectionLost);
        assert_eq!(connection_closed().message, "The connection was closed");
        assert_eq!(invalid_range(), Status::internal("Invalid range"));
    }
}
