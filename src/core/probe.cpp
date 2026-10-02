// SPDX-License-Identifier: LGPL-2.1-or-later
#include "probe.h"
#include "paths.h"

#include <QtCore/QBuffer>
#include <QtCore/QUuid>

namespace NetVfs {

const char ProbeFilePrefix[] = ".netvfs-probe-";

Result verifyAccess(Backend *backend, const QString &dir, qint64 *freeBytes)
{
    if (freeBytes)
        *freeBytes = -1;

    QString target;
    Result r = Paths::normalize(dir, &target);
    if (!r.ok())
        return r;
    r = backend->makePath(target);
    if (!r.ok())
        return r;

    // SEC-6: the probe carries no device-identifying data.
    const QString name = QLatin1String(ProbeFilePrefix)
            + QUuid::createUuid().toString().mid(1, 36).remove(QLatin1Char('-'));
    const QString path = Paths::join(target, name);
    QByteArray content("netvfs write test\n");
    QBuffer buffer(&content);
    buffer.open(QIODevice::ReadOnly);
    r = backend->upload(&buffer, path, UploadOptions(), nullptr);
    if (!r.ok()) {
        backend->remove(path);
        return r;
    }
    r = backend->remove(path);
    if (!r.ok())
        return r;

    qint64 available = -1;
    r = backend->freeSpace(target, &available);
    if (r.ok() && freeBytes)
        *freeBytes = available;
    if (r.error() == Error::Unsupported)
        r = Result::success();
    return r;
}

} // namespace NetVfs
