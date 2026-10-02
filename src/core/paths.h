// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PATHS_H
#define NETVFS_PATHS_H

#include "error.h"

#include <QtCore/QStringList>

namespace NetVfs::Paths {

// SPEC C-15. '/' separated; repeated separators collapse; a trailing separator
// is dropped; a leading separator is kept (absolute path, backend-defined
// meaning). Components "." and "..", and NUL characters, are rejected.
// An empty input normalizes to "" (the backend's base directory).
NETVFS_EXPORT Result normalize(const QString &path, QString *normalized);

NETVFS_EXPORT bool isAbsolute(const QString &normalizedPath);
NETVFS_EXPORT QStringList components(const QString &normalizedPath);
NETVFS_EXPORT QString join(const QString &dir, const QString &name);
NETVFS_EXPORT QString parent(const QString &normalizedPath);
NETVFS_EXPORT QString fileName(const QString &normalizedPath);

// SPEC-smb M-9: a component must not contain \ : * ? " < > | or end in a
// space or a dot. Returns an empty string when acceptable, else the reason.
NETVFS_EXPORT QString windowsComponentProblem(const QString &component);
NETVFS_EXPORT Result checkWindowsPath(const QString &normalizedPath);

} // namespace NetVfs::Paths

#endif
