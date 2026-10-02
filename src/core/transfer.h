// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TRANSFER_H
#define NETVFS_TRANSFER_H

#include "backend.h"

#include <QtCore/QDateTime>

namespace NetVfs {
namespace Transfer {

NETVFS_EXPORT QString partName(const QString &path);   // "<path>.part"

// SPEC C-12, C-13: free-space check, upload to "<final>.part", size check
// against bytes sent, rename to "<final>". The .part file is removed
// (best effort) on any failure. `size` is the expected size, or -1 if unknown
// (then the free-space check is skipped).
NETVFS_EXPORT Result upload(Backend *backend, QIODevice *source, qint64 size,
                            const QString &finalPath, Progress *progress = nullptr);
NETVFS_EXPORT Result uploadFile(Backend *backend, const QString &localPath,
                                const QString &finalPath, Progress *progress = nullptr);

// SPEC 8.6: download to "<local>.part", flush, size check, rename to "<local>"
// (replacing it). The local .part file is removed on failure.
NETVFS_EXPORT Result downloadFile(Backend *backend, const QString &remotePath,
                                  const QString &localPath, Progress *progress = nullptr);

// SPEC 8.4 step 2: remove "*.part" regular files in `dir` last modified
// before `now - maxAgeSecs`. A missing directory is not an error.
NETVFS_EXPORT Result removeStaleParts(Backend *backend, const QString &dir,
                                      const QDateTime &now = QDateTime::currentDateTimeUtc(),
                                      qint64 maxAgeSecs = 24 * 60 * 60);

} // namespace Transfer
} // namespace NetVfs

#endif
