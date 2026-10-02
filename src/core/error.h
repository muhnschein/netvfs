// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ERROR_H
#define NETVFS_ERROR_H

#include "netvfs_global.h"

#include <QtCore/QString>

namespace NetVfs {

// Single error taxonomy (SPEC 5.4). Library-specific codes never leave a backend.
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
    Internal
};

NETVFS_EXPORT QString errorName(Error error);
NETVFS_EXPORT Error errorFromName(const QString &name);

class NETVFS_EXPORT Result
{
public:
    Result() = default;
    explicit Result(Error error, const QString &message = QString())
        : m_error(error), m_message(message) {}

    static Result success() { return Result(); }

    bool ok() const { return m_error == Error::None; }
    Error error() const { return m_error; }
    QString message() const { return m_message; }

    // "<ErrorName>: <message>" or just the name; suitable for logs and Buteo messages.
    QString toString() const;

private:
    Error m_error = Error::None;
    QString m_message;
};

} // namespace NetVfs

#endif
