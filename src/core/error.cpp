// SPDX-License-Identifier: LGPL-2.1-or-later
#include "error.h"

#include <array>

namespace NetVfs {

namespace {
struct ErrorNameEntry {
    Error error;
    const char *name;
};

const std::array<ErrorNameEntry, 25> errorNames = { {
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
    { Error::ConnectionLost, "ConnectionLost" },
    { Error::NotADirectory, "NotADirectory" },
    { Error::IsADirectory, "IsADirectory" },
    { Error::DirectoryNotEmpty, "DirectoryNotEmpty" },
    { Error::InvalidName, "InvalidName" },
    { Error::ReadOnlyFilesystem, "ReadOnlyFilesystem" },
    { Error::Locked, "Locked" },
    { Error::TooManyConnections, "TooManyConnections" },
    { Error::RateLimited, "RateLimited" },
    { Error::NotModified, "NotModified" },
} };
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
