// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ERROR_H
#define NETVFS_ERROR_H

#include "netvfs_global.h"

#include <QtCore/QString>

namespace NetVfs {

// Single error taxonomy. Backend-specific codes never leave a backend. Values only appended;
// errorName() strings stable.
enum class Error {
    None,
    Canceled,
    NetworkUnreachable,
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
    ConnectionLost,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    InvalidName,
    ReadOnlyFilesystem,
    Locked,
    TooManyConnections,
    RateLimited
};

NETVFS_EXPORT QString errorName(Error error);
NETVFS_EXPORT Error errorFromName(const QString &name);

class NETVFS_EXPORT Result
{
public:
    Result() = default;
    explicit Result(Error error, const QString &message = QString())
        : m_error(error), m_message(message) {}
    // `detail`: protocol status for logs and "Details" view. Never secrets.
    Result(Error error, const QString &message, const QString &detail, qint64 retryAfterMs = -1)
        : m_error(error), m_message(message), m_detail(detail), m_retryAfterMs(retryAfterMs) {}

    static Result success() { return Result(); }

    bool ok() const { return m_error == Error::None; }
    Error error() const { return m_error; }
    QString message() const { return m_message; }
    QString detail() const { return m_detail; }
    qint64 retryAfterMs() const { return m_retryAfterMs; }

    Result &setDetail(const QString &detail) { m_detail = detail; return *this; }
    Result &setRetryAfterMs(qint64 ms) { m_retryAfterMs = ms; return *this; }

    QString toString() const;

private:
    Error m_error = Error::None;
    QString m_message;
    QString m_detail;
    qint64 m_retryAfterMs = -1;
};

}
#endif
