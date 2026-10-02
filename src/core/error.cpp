// SPDX-License-Identifier: LGPL-2.1-or-later
#include "error.h"

namespace NetVfs {

namespace {
struct ErrorNameEntry {
    Error error;
    const char *name;
};

const ErrorNameEntry errorNames[] = {
    { Error::None, "None" },
    { Error::Canceled, "Canceled" },
    { Error::NetworkUnreachable, "NetworkUnreachable" },
    { Error::Timeout, "Timeout" },
    { Error::ServerIdentityUnknown, "ServerIdentityUnknown" },
    { Error::ServerIdentityChanged, "ServerIdentityChanged" },
    { Error::AuthFailed, "AuthFailed" },
    { Error::SecurityPolicy, "SecurityPolicy" },
    { Error::PermissionDenied, "PermissionDenied" },
    { Error::NotFound, "NotFound" },
    { Error::AlreadyExists, "AlreadyExists" },
    { Error::NoSpace, "NoSpace" },
    { Error::Unsupported, "Unsupported" },
    { Error::ProtocolError, "ProtocolError" },
    { Error::Internal, "Internal" },
};
} // namespace

QString errorName(Error error)
{
    for (const ErrorNameEntry &entry : errorNames) {
        if (entry.error == error)
            return QLatin1String(entry.name);
    }
    return QStringLiteral("Internal");
}

Error errorFromName(const QString &name)
{
    for (const ErrorNameEntry &entry : errorNames) {
        if (name == QLatin1String(entry.name))
            return entry.error;
    }
    return Error::Internal;
}

QString Result::toString() const
{
    if (m_message.isEmpty())
        return errorName(m_error);
    return errorName(m_error) + QStringLiteral(": ") + m_message;
}

} // namespace NetVfs
