// SPDX-License-Identifier: LGPL-2.1-or-later
//! HTTP status codes as netvfs errors.

use http::{HeaderMap, StatusCode, header};
use netvfs_vfs::{ErrorName, Status};
use std::time::{Duration, SystemTime};

/// What the request was for; some codes mean different things per method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// MKCOL: 405 means the name is taken.
    MakeDir,
    /// PUT: 405 means a folder is there.
    Put,
    /// Anything else.
    Other,
}

/// Longest `Retry-After` taken: a day.
const MAX_RETRY_AFTER: Duration = Duration::from_hours(24);

/// `Retry-After` (seconds or HTTP date) in ms from `now`, capped at a day; `None` when absent or unreadable.
#[must_use]
pub fn retry_after_ms(headers: &HeaderMap, now: SystemTime) -> Option<i64> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    let wait = match value.parse::<u64>() {
        Ok(secs) => Duration::from_secs(secs),
        Err(_) => httpdate::parse_http_date(value).ok()?.duration_since(now).unwrap_or_default(),
    };
    i64::try_from(wait.min(MAX_RETRY_AFTER).as_millis()).ok()
}

/// Whether `e` is a 400 or 500 answer: what Apache mod_dav gives for a path below a file and a MOVE into a missing
/// folder.
#[must_use]
pub fn unresolved(e: &Status) -> bool {
    e.name == ErrorName::ProtocolError
        && (e.detail.starts_with("HTTP 400 ") || e.detail.starts_with("HTTP 500 "))
}

/// The error of a non-2xx answer to `op`.
#[must_use]
pub fn error(code: StatusCode, op: Op, headers: &HeaderMap, now: SystemTime) -> Status {
    let detail = format!("HTTP {code}");
    let (name, message) = match code.as_u16() {
        400 => (ErrorName::ProtocolError, "The server rejected the request as malformed"),
        401 => (ErrorName::AuthFailed, "The server did not accept the user name or password"),
        403 => (ErrorName::PermissionDenied, "Permission denied"),
        404 | 410 => (ErrorName::NotFound, "No such file or folder"),
        405 if op == Op::MakeDir => (ErrorName::AlreadyExists, "The name is taken"),
        405 if op == Op::Put => (ErrorName::IsADirectory, "A folder has this name"),
        405 => (ErrorName::Unsupported, "The server does not allow this here"),
        409 => (ErrorName::NotFound, "The parent folder does not exist"),
        412 => (ErrorName::AlreadyExists, "The target already exists"),
        413 => (ErrorName::Unsupported, "The server refuses a file this large"),
        414 => (ErrorName::InvalidName, "The path is too long for the server"),
        415 | 501 => (ErrorName::Unsupported, "The server does not support this request"),
        423 => (ErrorName::Locked, "The file is locked"),
        507 => (ErrorName::NoSpace, "Not enough space on the server"),
        429 | 503 => {
            let wait = retry_after_ms(headers, now);
            if code.as_u16() == 429 || wait.is_some() {
                let s = Status::new(ErrorName::RateLimited, "The server asks to try again later")
                    .with_detail(detail);
                return s.with_retry_after_ms(wait.unwrap_or(-1));
            }
            (ErrorName::ProtocolError, "The server is unavailable")
        }
        300..=399 => (ErrorName::ProtocolError, "The server redirects elsewhere; check the address"),
        _ => (ErrorName::ProtocolError, "The server answered with an error"),
    };
    Status::new(name, message).with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn name(code: u16, op: Op) -> ErrorName {
        error(StatusCode::from_u16(code).unwrap(), op, &HeaderMap::new(), SystemTime::UNIX_EPOCH).name
    }

    #[test]
    fn codes_map_to_names() {
        use ErrorName::*;
        let table = [
            (400, ProtocolError),
            (401, AuthFailed),
            (403, PermissionDenied),
            (404, NotFound),
            (410, NotFound),
            (405, Unsupported),
            (409, NotFound),
            (412, AlreadyExists),
            (413, Unsupported),
            (414, InvalidName),
            (415, Unsupported),
            (501, Unsupported),
            (423, Locked),
            (507, NoSpace),
            (429, RateLimited),
            (503, ProtocolError),
            (500, ProtocolError),
            (301, ProtocolError),
            (399, ProtocolError),
        ];
        for (code, want) in table {
            assert_eq!(name(code, Op::Other), want, "{code}");
        }
        assert_eq!(name(405, Op::MakeDir), AlreadyExists);
        assert_eq!(name(405, Op::Put), IsADirectory);
        assert_eq!(name(404, Op::Put), NotFound);
        let s = error(StatusCode::NOT_FOUND, Op::Other, &HeaderMap::new(), SystemTime::UNIX_EPOCH);
        assert_eq!(s.detail, "HTTP 404 Not Found");
        // Protocol errors say what went wrong.
        let message = |code| {
            error(StatusCode::from_u16(code).unwrap(), Op::Other, &HeaderMap::new(), SystemTime::UNIX_EPOCH)
                .message
        };
        assert_eq!(message(400), "The server rejected the request as malformed");
        assert_eq!(message(302), "The server redirects elsewhere; check the address");
        assert_eq!(message(502), "The server answered with an error");
    }

    #[test]
    fn bad_requests_and_server_errors_are_unresolved() {
        let of = |code| {
            error(StatusCode::from_u16(code).unwrap(), Op::Other, &HeaderMap::new(), SystemTime::UNIX_EPOCH)
        };
        assert!(unresolved(&of(400)) && unresolved(&of(500)));
        for code in [404, 405, 409, 501, 502, 503] {
            assert!(!unresolved(&of(code)), "{code}");
        }
        let lookalike = Status::new(ErrorName::NotFound, "x").with_detail("HTTP 400 Bad Request");
        assert!(!unresolved(&lookalike));
    }

    #[test]
    fn retry_after_seconds_and_dates() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut h = HeaderMap::new();
        assert_eq!(retry_after_ms(&h, now), None);
        h.insert(header::RETRY_AFTER, HeaderValue::from_static(" 7 "));
        assert_eq!(retry_after_ms(&h, now), Some(7000));
        let s = error(StatusCode::SERVICE_UNAVAILABLE, Op::Other, &h, now);
        assert_eq!((s.name, s.retry_after_ms), (ErrorName::RateLimited, 7000));
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("Mon, 12 Jan 1970 13:46:50 GMT"));
        assert_eq!(retry_after_ms(&h, now), Some(10_000));
        // Past dates: no wait; long waits: a day.
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(retry_after_ms(&h, now), Some(0));
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("99999999"));
        assert_eq!(retry_after_ms(&h, now), Some(86_400_000));
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("soon"));
        assert_eq!(retry_after_ms(&h, now), None);
        let s = error(StatusCode::TOO_MANY_REQUESTS, Op::Other, &h, now);
        assert_eq!((s.name, s.retry_after_ms), (ErrorName::RateLimited, -1));
    }
}
