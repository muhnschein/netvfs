// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_BACKUPSTEPS_H
#define NETVFS_BUTEO_BACKUPSTEPS_H

#include "backend.h"

#include <QtCore/QDateTime>
#include <QtCore/QStringList>

namespace NetVfs::BackupSteps {
Result remoteDirectory(const QString &backupsPath, const QString &deviceId, QString *remoteDir);

Result preflight(Backend *backend, const QString &remoteDir,
                 const QDateTime &now = QDateTime::currentDateTimeUtc());

Result uploadArchive(Backend *backend, const QString &localPath, const QString &remoteDir);

Result listBackups(Backend *backend, const QString &remoteDir, QStringList *paths);

Result restoreBackup(Backend *backend, const QString &remoteDir, const QString &localPath);

}
#endif
