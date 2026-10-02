// SPDX-License-Identifier: LGPL-2.1-or-later
#include "types.h"
#include "secure.h"

namespace NetVfs {

QString ServerIdentity::toPin() const
{
    if (isEmpty())
        return QString();
    return algorithm + QLatin1Char(' ') + QString::fromLatin1(publicKey.toBase64());
}

ServerIdentity ServerIdentity::fromPin(const QString &pin)
{
    ServerIdentity identity;
    const QStringList parts = pin.trimmed().split(QLatin1Char(' '), NETVFS_SKIP_EMPTY_PARTS);
    if (parts.size() != 2)
        return identity;
    const QByteArray blob = QByteArray::fromBase64(parts.at(1).toLatin1());
    if (blob.isEmpty() || blob.toBase64() != parts.at(1).toLatin1())
        return identity;
    identity.algorithm = parts.at(0);
    identity.publicKey = blob;
    return identity;
}

// Deep copies, so wiping ours never touches the caller's buffer.
Credentials::Credentials(const QString &user, const QByteArray &secretData)
    : userName(user)
    , secret(secretData.constData(), secretData.size())
{
}

Credentials::Credentials(const Credentials &other)
    : userName(other.userName)
    , secret(other.secret.constData(), other.secret.size())
{
}

Credentials &Credentials::operator=(const Credentials &other)
{
    if (this != &other) {
        wipe();
        userName = other.userName;
        secret = QByteArray(other.secret.constData(), other.secret.size());
    }
    return *this;
}

Credentials::~Credentials()
{
    wipe();
}

void Credentials::wipe()
{
    secureWipe(secret);
}

} // namespace NetVfs
