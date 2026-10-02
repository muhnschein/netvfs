// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sshkeys.h"
#include "secure.h"
#include "transfer.h"

#include <QtCore/QBuffer>

namespace NetVfs {

const char KeySecretPrefix[] = "netvfs-key-v1:";

namespace {
const char SshDir[] = ".ssh";
const char AuthorizedKeys[] = ".ssh/authorized_keys";

// "<algorithm> <base64>" of an authorized_keys line, ignoring options and comment.
QByteArray keyPart(const QByteArray &line)
{
    const QList<QByteArray> fields = line.simplified().split(' ');
    for (int i = 0; i + 1 < fields.size(); ++i) {
        if (fields.at(i).startsWith("ssh-") || fields.at(i).startsWith("ecdsa-")
                || fields.at(i).startsWith("sk-"))
            return fields.at(i) + ' ' + fields.at(i + 1);
    }
    return QByteArray();
}
} // namespace

SshKeyMaterial::~SshKeyMaterial()
{
    wipe();
}

void SshKeyMaterial::wipe()
{
    secureWipe(privateKey);
}

SshKeyTools::~SshKeyTools() = default;

QByteArray encodeKeySecret(const QByteArray &privateKey)
{
    return QByteArray(KeySecretPrefix) + privateKey.toBase64();
}

bool isKeySecret(const QByteArray &secret)
{
    return secret.startsWith(KeySecretPrefix);
}

bool decodeKeySecret(const QByteArray &secret, QByteArray *privateKey)
{
    if (!isKeySecret(secret))
        return false;
    const QByteArray encoded = secret.mid(static_cast<int>(sizeof(KeySecretPrefix)) - 1);
    QByteArray decoded = QByteArray::fromBase64(encoded);
    if (decoded.isEmpty() || decoded.toBase64() != encoded) {
        secureWipe(decoded);
        return false;
    }
    if (privateKey)
        *privateKey = decoded;
    secureWipe(decoded);
    return true;
}

Result installAuthorizedKey(Backend *backend, const QString &publicLine)
{
    const QByteArray line = publicLine.trimmed().toUtf8();
    const QByteArray key = keyPart(line);
    if (key.isEmpty() || line.contains('\n'))
        return Result(Error::Internal, QStringLiteral("Not an authorized_keys line"));

    Result r = backend->makePath(QLatin1String(SshDir));
    if (!r.ok())
        return r;

    QByteArray existing;
    Entry entry;
    r = backend->stat(QLatin1String(AuthorizedKeys), &entry);
    if (r.ok()) {
        QBuffer sink(&existing);
        sink.open(QIODevice::WriteOnly);
        r = backend->download(QLatin1String(AuthorizedKeys), &sink, nullptr);
        if (!r.ok())
            return r;
    } else if (r.error() != Error::NotFound) {
        return r;
    }

    for (const QByteArray &present : existing.split('\n')) {
        if (keyPart(present) == key)
            return Result::success();
    }

    QByteArray updated = existing;
    if (!updated.isEmpty() && !updated.endsWith('\n'))
        updated.append('\n');
    updated.append(line).append('\n');
    QBuffer source(&updated);
    source.open(QIODevice::ReadOnly);
    return Transfer::upload(backend, &source, updated.size(), QLatin1String(AuthorizedKeys));
}

} // namespace NetVfs
