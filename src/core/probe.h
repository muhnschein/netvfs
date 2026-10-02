// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PROBE_H
#define NETVFS_PROBE_H

#include "backend.h"

namespace NetVfs {

// SPEC 7.2 verify() after authentication: makePath(dir), write and delete
// ".netvfs-probe-<random>", query free space. `*freeBytes` is -1 when the
// server cannot report it.
NETVFS_EXPORT Result verifyAccess(Backend *backend, const QString &dir, qint64 *freeBytes = nullptr);

NETVFS_EXPORT extern const char ProbeFilePrefix[];   // ".netvfs-probe-"

} // namespace NetVfs

#endif
