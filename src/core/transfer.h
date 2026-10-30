// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TRANSFER_H
#define NETVFS_TRANSFER_H

#include "backend.h"

#include <QtCore/QDateTime>

namespace NetVfs::Transfer {

NETVFS_EXPORT QString partName(const QString &path);
// Defaults are the backup policy: "<name>.part" temporary, size verification, Replace on commit,
// files 0600.
struct TransferPolicy {
    QString tempName;
    bool useTempName = true;
    bool verifySize = true;
    RenameMode commitMode = RenameMode::Replace;
    qint32 createMode = 0600;
    QDateTime modified;
    // Resume: openWrite(Resume) on the temporary name after checking `resumeOffset` equals its
    // remote size; `source` positioned to it first. Needs WriteResume.
    bool resume = false;
    qint64 resumeOffset = 0;
};

// Free-space check, upload to the temporary name, size check against bytes sent, rename to
// "<final>" with policy.commitMode. Temporary removed (best effort) on failure, except canceled or
// failed resumable upload, which keeps it. `size` -1: unknown, free-space check skipped.
NETVFS_EXPORT Result upload(Backend *backend, QIODevice *source, qint64 size,
                            const QString &finalPath, Progress *progress = nullptr,
                            const TransferPolicy &policy = TransferPolicy());
NETVFS_EXPORT Result uploadFile(Backend *backend, const QString &localPath,
                                const QString &finalPath, Progress *progress = nullptr,
                                const TransferPolicy &policy = TransferPolicy());

// Download to "<local>.part", flush, size check, rename to "<local>" (replacing). The .part is
// removed on failure.
NETVFS_EXPORT Result downloadFile(Backend *backend, const QString &remotePath,
                                  const QString &localPath, Progress *progress = nullptr);

// Removes regular files in `dir` matching `pattern` (wildcard, default "*.part") older than `now -
// maxAgeSecs`. Missing directory is not an error.
NETVFS_EXPORT Result removeStaleParts(Backend *backend, const QString &dir,
                                      const QDateTime &now = QDateTime::currentDateTimeUtc(),
                                      qint64 maxAgeSecs = 24 * 60 * 60,
                                      const QString &pattern = QStringLiteral("*.part"));

}
#endif
