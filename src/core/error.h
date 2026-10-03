// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ERROR_H
#define NETVFS_ERROR_H

#include "netvfs_global.h"

#include <QtCore/QString>

namespace NetVfs {

// Single error taxonomy (SPEC 5.4). Library-specific codes never leave a backend.
// Values are only ever appended; errorName() strings are stable (SPEC-v2 XC-21).
enum class Error {
    None,
    Canceled,
    NetworkUnreachable,     // could not reach the server
    Timeout,
    ServerIdentityUnknown,
    ServerIdentityChanged,
    AuthFailed,
    SecurityPolicy,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    NoSpace,
    Unsupported,
    ProtocolError,
    Internal,
    // Added with API v2, see XC-21
    ConnectionLost,         // an established connection dropped
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    InvalidName,
    ReadOnlyFilesystem,
    Locked,                 // SMB sharing violation, WebDAV 423
    TooManyConnections,     // MaxSessions, SMB/HTTP connection limits
    RateLimited,            // HTTP 429/503 with Retry-After
    NotModified             // internal: WebDAV conditional requests
};

NETVFS_EXPORT QString errorName(Error error);
NETVFS_EXPORT Error errorFromName(const QString &name);

class NETVFS_EXPORT Result
{
public:
    Result() = default;
    explicit Result(Error error, const QString &message = QString())
        : m_error(error), m_message(message) {}
    // XC-24: `detail` is the protocol status for logs and a "Details" view
    // (never secrets; C-17 debug rules apply to paths in it).
    Result(Error error, const QString &message, const QString &detail, qint64 retryAfterMs = -1)
        : m_error(error), m_message(message), m_detail(detail), m_retryAfterMs(retryAfterMs) {}

    static Result success() { return Result(); }

    bool ok() const { return m_error == Error::None; }
    Error error() const { return m_error; }
    QString message() const { return m_message; }
    QString detail() const { return m_detail; }
    qint64 retryAfterMs() const { return m_retryAfterMs; }   // -1: none

    Result &setDetail(const QString &detail) { m_detail = detail; return *this; }
    Result &setRetryAfterMs(qint64 ms) { m_retryAfterMs = ms; return *this; }

    // "<ErrorName>: <message>" or just the name; suitable for logs and Buteo messages.
    QString toString() const;

private:
    Error m_error = Error::None;
    QString m_message;
    QString m_detail;
    qint64 m_retryAfterMs = -1;
};

} // namespace NetVfs

#endif
