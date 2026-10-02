// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backupsteps.h"
#include "paths.h"
#include "transfer.h"

#include <QtCore/QFileInfo>

namespace NetVfs::BackupSteps {

namespace {
const char PartSuffix[] = ".part";
}

Result remoteDirectory(const QString &backupsPath, const QString &deviceId, QString *remoteDir)
{
    const QString id = deviceId.trimmed();
    if (id.isEmpty() || id.contains(QLatin1Char('/')) || id == QLatin1String(".") || id == QLatin1String(".."))
        return Result(Error::Internal, QStringLiteral("The backup service returned an unusable device id \"%1\"").arg(deviceId));
    return Paths::normalize(backupsPath + QLatin1Char('/') + id, remoteDir);
}

Result preflight(Backend *backend, const QString &remoteDir, const QDateTime &now)
{
    if (const Result r = backend->makePath(remoteDir); !r.ok())
        return r;
    return Transfer::removeStaleParts(backend, remoteDir, now);
}

Result uploadArchive(Backend *backend, const QString &localPath, const QString &remoteDir)
{
    return Transfer::uploadFile(backend, localPath, Paths::join(remoteDir, QFileInfo(localPath).fileName()));
}

Result listBackups(Backend *backend, const QString &remoteDir, QStringList *paths)
{
    QVector<Entry> entries;
    const Result r = backend->list(remoteDir, &entries);
    if (r.error() == Error::NotFound)
        return Result::success();
    if (!r.ok())
        return r;

    QStringList names;
    for (const Entry &entry : entries) {
        if (!entry.isDir && !entry.name.endsWith(QLatin1String(PartSuffix)))
            names.append(entry.name);
    }
    names.sort();
    for (const QString &name : names)
        paths->append(remoteDir + QLatin1Char('/') + name);
    return r;
}

Result restoreBackup(Backend *backend, const QString &remoteDir, const QString &localPath)
{
    const QString name = QFileInfo(localPath).fileName();
    if (name.isEmpty())
        return Result(Error::Internal, QStringLiteral("The restore target \"%1\" has no file name").arg(localPath));

    Result r = Transfer::downloadFile(backend, Paths::join(remoteDir, name), localPath);
    if (r.error() == Error::NotFound)
        r = Result(Error::NotFound, QStringLiteral("The backup %1 does not exist in %2 on the server").arg(name, remoteDir));
    return r;
}

} // namespace NetVfs::BackupSteps
