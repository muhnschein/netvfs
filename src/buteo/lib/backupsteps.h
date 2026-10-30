// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_BACKUPSTEPS_H
#define NETVFS_BUTEO_BACKUPSTEPS_H

#include "backend.h"

#include <QtCore/QDateTime>
#include <QtCore/QStringList>

// Network steps of the backup operations. Each runs on a worker thread over an established
// connection.
namespace NetVfs::BackupSteps {

// <backups_path>/<backupFileDeviceId()>, normalized. Device id must be a single path component.
Result remoteDirectory(const QString &backupsPath, const QString &deviceId, QString *remoteDir);

// Create the remote directory and remove stale .part files.
Result preflight(Backend *backend, const QString &remoteDir,
                 const QDateTime &now = QDateTime::currentDateTimeUtc());

// Upload the archive under its own name.
Result uploadArchive(Backend *backend, const QString &localPath, const QString &remoteDir);

// "<remoteDir>/<name>" for each regular file not ending in ".part", sorted. Missing directory =
// empty list.
Result listBackups(Backend *backend, const QString &remoteDir, QStringList *paths);

// File name of `localPath` selects the remote file; download via "<localPath>.part".
Result restoreBackup(Backend *backend, const QString &remoteDir, const QString &localPath);

}
#endif
