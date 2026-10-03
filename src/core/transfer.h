// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TRANSFER_H
#define NETVFS_TRANSFER_H

#include "backend.h"

#include <QtCore/QDateTime>

namespace NetVfs::Transfer {

NETVFS_EXPORT QString partName(const QString &path);   // "<path>.part"

// SPEC-v2 XH-1 (amends C-12, C-13, 8.6). The defaults are the backup policy:
// "<name>.part" temporary, size verification, Replace on commit, files 0600
// (S-20 preserved through XC-23).
struct TransferPolicy {
    QString tempName;                 // empty: partName(final)
    bool useTempName = true;          // consumers pass false when AtomicPut
    bool verifySize = true;
    RenameMode commitMode = RenameMode::Replace;
    qint32 createMode = 0600;         // -1: backend default
    QDateTime modified;               // applied when SetModified(OnUpload)
    // Resume an interrupted upload: openWrite(Resume) on the temporary name
    // after checking that `resumeOffset` equals its remote size; `source` is
    // positioned (seek or skip) to that offset first. Needs WriteResume.
    bool resume = false;
    qint64 resumeOffset = 0;
};

// SPEC C-12, C-13: free-space check, upload to the temporary name, size
// check against bytes sent, rename to "<final>" with policy.commitMode. The
// temporary file is removed (best effort) on any failure except a canceled
// or failed resumable upload (resume == true), which keeps it for the next
// attempt. `size` is the expected total size, or -1 if unknown (then the
// free-space check is skipped).
NETVFS_EXPORT Result upload(Backend *backend, QIODevice *source, qint64 size,
                            const QString &finalPath, Progress *progress = nullptr,
                            const TransferPolicy &policy = TransferPolicy());
NETVFS_EXPORT Result uploadFile(Backend *backend, const QString &localPath,
                                const QString &finalPath, Progress *progress = nullptr,
                                const TransferPolicy &policy = TransferPolicy());

// SPEC 8.6: download to "<local>.part", flush, size check, rename to "<local>"
// (replacing it). The local .part file is removed on failure.
NETVFS_EXPORT Result downloadFile(Backend *backend, const QString &remotePath,
                                  const QString &localPath, Progress *progress = nullptr);

// SPEC 8.4 step 2: remove regular files in `dir` matching `pattern` (a
// wildcard, default "*.part") last modified before `now - maxAgeSecs`. A
// missing directory is not an error.
NETVFS_EXPORT Result removeStaleParts(Backend *backend, const QString &dir,
                                      const QDateTime &now = QDateTime::currentDateTimeUtc(),
                                      qint64 maxAgeSecs = 24 * 60 * 60,
                                      const QString &pattern = QStringLiteral("*.part"));

} // namespace NetVfs::Transfer

#endif
