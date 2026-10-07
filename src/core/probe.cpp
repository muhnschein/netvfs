// SPDX-License-Identifier: LGPL-2.1-or-later
#include "probe.h"
#include "logging.h"
#include "paths.h"

#include <QtCore/QBuffer>
#include <QtCore/QUuid>

namespace NetVfs {

const char ProbeFilePrefix[] = ".netvfs-probe-";
const char DirModeOption[] = "dir_mode";
const char BackupDirMode[] = "0700";

ConnectionParams withBackupDirMode(const ConnectionParams &params)
{
    ConnectionParams result = params;
    result.options.insert(QLatin1String(DirModeOption), QLatin1String(BackupDirMode));
    return result;
}

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

    // Best effort, as in verifyBrowseAccess(): the probe file already proved
    // write access. Some servers drop the connection on this query (Samba
    // with quotas on ZFS); free space is then unknown, not a failed verify.
    qint64 available = -1;
    r = backend->freeSpace(target, &available);
    if (r.error() == Error::Canceled)
        return r;
    if (r.ok() && freeBytes)
        *freeBytes = available;
    if (!r.ok() && r.error() != Error::Unsupported)
        qCDebug(lcNetVfsCore) << "Free space unknown:" << r.toString();
    return Result::success();
}

Result verifyBrowseAccess(Backend *backend, const QString &root, qint64 *freeBytes)
{
    if (freeBytes)
        *freeBytes = -1;

    QString target;
    Result r = Paths::normalize(root, &target);
    if (!r.ok())
        return r;
    Entry entry;
    r = backend->stat(target, &entry);
    if (!r.ok())
        return r;
    if (!entry.isDir())
        return Result(Error::NotADirectory, QStringLiteral("The start folder is not a folder"));

    if (qint64 available = -1; backend->freeSpace(target, &available).ok() && freeBytes)
        *freeBytes = available;
    return Result::success();
}

} // namespace NetVfs
