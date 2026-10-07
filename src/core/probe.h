// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PROBE_H
#define NETVFS_PROBE_H

#include "backend.h"

namespace NetVfs {

// SPEC 7.2 verify() after authentication: makePath(dir), write and delete
// ".netvfs-probe-<random>", query free space best effort. `*freeBytes` is -1
// when the server cannot report it or the query fails (only Canceled stops).
NETVFS_EXPORT Result verifyAccess(Backend *backend, const QString &dir, qint64 *freeBytes = nullptr);

NETVFS_EXPORT extern const char ProbeFilePrefix[];   // ".netvfs-probe-"

// The Files counterpart (SPEC-v2-review 2.19): after authentication, stat
// `root` ("" = the backend's base folder), which must be a folder
// (NotADirectory otherwise), and query free space best effort. Nothing is
// created or written, so read-only shares and guest access verify.
NETVFS_EXPORT Result verifyBrowseAccess(Backend *backend, const QString &root, qint64 *freeBytes = nullptr);

// SPEC-sftp S-20 kept by SPEC-v2 XC-23: folders that backups create are
// private (files are, through TransferPolicy::createMode). makeDir() has no
// mode, so backup callers set the connection option "dir_mode" (octal);
// backends without POSIX modes ignore it, others default to the server's
// umask without it.
NETVFS_EXPORT extern const char DirModeOption[];     // "dir_mode"
NETVFS_EXPORT extern const char BackupDirMode[];     // "0700"
// `params` with dir_mode = BackupDirMode.
NETVFS_EXPORT ConnectionParams withBackupDirMode(const ConnectionParams &params);

} // namespace NetVfs

#endif
