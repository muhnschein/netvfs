// SPDX-License-Identifier: LGPL-2.1-or-later
#include "types.h"
#include "secure.h"

#include <QtCore/QCryptographicHash>

#include <algorithm>
#include <array>

namespace NetVfs {

bool Entry::isDir() const
{
    return type == EntryType::Directory || (type == EntryType::Symlink && targetType == EntryType::Directory);
}

bool Entry::isFile() const
{
    return type == EntryType::File || (type == EntryType::Symlink && targetType == EntryType::File);
}

namespace {
struct CapabilityName {
    Capability capability;
    const char *name;
};

const std::array<CapabilityName, 22> capabilityNames = { {
    { Capability::Symlinks, "Symlinks" },
    { Capability::Hardlinks, "Hardlinks" },
    { Capability::PosixModes, "PosixModes" },
    { Capability::Ownership, "Ownership" },
    { Capability::SetModified, "SetModified" },
    { Capability::SetModifiedOnUpload, "SetModifiedOnUpload" },
    { Capability::ReadHandles, "ReadHandles" },
    { Capability::EfficientRanges, "EfficientRanges" },
    { Capability::WriteResume, "WriteResume" },
    { Capability::AtomicPut, "AtomicPut" },
    { Capability::AtomicReplace, "AtomicReplace" },
    { Capability::NativeNoReplace, "NativeNoReplace" },
    { Capability::ServerCopy, "ServerCopy" },
    { Capability::ServerCopyRecursive, "ServerCopyRecursive" },
    { Capability::RecursiveDelete, "RecursiveDelete" },
    { Capability::SpaceInfo, "SpaceInfo" },
    { Capability::Checksums, "Checksums" },
    { Capability::CaseInsensitive, "CaseInsensitive" },
    { Capability::WindowsNames, "WindowsNames" },
    { Capability::ShareEnumeration, "ShareEnumeration" },
    { Capability::ShellExec, "ShellExec" },
    { Capability::ETags, "ETags" },
} };
} // namespace

QString capabilityName(Capability c)
{
    for (const CapabilityName &entry : capabilityNames) {
        if (entry.capability == c)
            return QLatin1String(entry.name);
    }
    return QString();
}

bool capabilityFromName(const QString &name, Capability *out)
{
    for (const CapabilityName &entry : capabilityNames) {
        if (name == QLatin1String(entry.name)) {
            if (out)
                *out = entry.capability;
            return true;
        }
    }
    return false;
}

QVector<Capability> allCapabilities()
{
    QVector<Capability> all;
    for (const CapabilityName &entry : capabilityNames)
        all << entry.capability;
    return all;
}

QStringList Capabilities::names() const
{
    QStringList result;
    for (const Capability c : flags)
        result << capabilityName(c);
    std::sort(result.begin(), result.end());
    return result;
}

AuthPrompter::~AuthPrompter() = default;

ServerIdentity ServerIdentity::fromTlsSpki(const QByteArray &spkiDer)
{
    ServerIdentity identity;
    if (spkiDer.isEmpty())
        return identity;
    identity.kind = Kind::TlsCertificate;
    identity.algorithm = QLatin1String(TlsAlgorithm);
    identity.publicKey = spkiDer;
    identity.fingerprint = QString::fromLatin1(
        QCryptographicHash::hash(spkiDer, QCryptographicHash::Sha256).toBase64());
    return identity;
}

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
    if (parts.at(0) == QLatin1String(TlsAlgorithm))
        return fromTlsSpki(blob);
    identity.kind = Kind::SshHostKey;
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
