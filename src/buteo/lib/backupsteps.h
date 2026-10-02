// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_BACKUPSTEPS_H
#define NETVFS_BUTEO_BACKUPSTEPS_H

#include "backend.h"

#include <QtCore/QDateTime>
#include <QtCore/QStringList>

// The network steps of the backup operations (SPEC 8.4 to 8.6). Each runs on
// a worker thread over an established connection.
namespace NetVfs::BackupSteps {

// SPEC B-2: <backups_path>/<backupFileDeviceId()>, normalized. The device id
// must be a single path component.
Result remoteDirectory(const QString &backupsPath, const QString &deviceId, QString *remoteDir);

// SPEC 8.4 step 2: create the remote directory and remove stale .part files.
Result preflight(Backend *backend, const QString &remoteDir,
                 const QDateTime &now = QDateTime::currentDateTimeUtc());

// SPEC 8.4 step 5: upload the archive under its own name (C-12, C-13).
Result uploadArchive(Backend *backend, const QString &localPath, const QString &remoteDir);

// SPEC 8.5: "<remoteDir>/<name>" for each regular file not ending in ".part",
// sorted. A missing directory is an empty list.
Result listBackups(Backend *backend, const QString &remoteDir, QStringList *paths);

// SPEC 8.6: the file name of `localPath` selects the remote file; download
// via "<localPath>.part".
Result restoreBackup(Backend *backend, const QString &remoteDir, const QString &localPath);

} // namespace NetVfs::BackupSteps

#endif
