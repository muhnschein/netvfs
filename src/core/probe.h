// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PROBE_H
#define NETVFS_PROBE_H

#include "backend.h"

namespace NetVfs {

// After authentication: makePath(dir), write and delete ".netvfs-probe-<random>", query free space
// best effort. `*freeBytes` -1 when unknown or the query fails (only Canceled stops).
NETVFS_EXPORT Result verifyAccess(Backend *backend, const QString &dir, qint64 *freeBytes = nullptr);

NETVFS_EXPORT extern const char ProbeFilePrefix[];
// Files counterpart: stat `root` ("" = base folder), must be a folder (NotADirectory); free space
// best effort. Writes nothing, so read-only shares and guest verify.
NETVFS_EXPORT Result verifyBrowseAccess(Backend *backend, const QString &root, qint64 *freeBytes = nullptr);

// Backup folders are private (files via TransferPolicy::createMode). makeDir() has no mode: callers
// set option "dir_mode" (octal); backends without POSIX modes ignore it.
NETVFS_EXPORT extern const char DirModeOption[];
NETVFS_EXPORT extern const char BackupDirMode[];
NETVFS_EXPORT ConnectionParams withBackupDirMode(const ConnectionParams &params);

}
#endif
