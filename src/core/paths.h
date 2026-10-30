// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PATHS_H
#define NETVFS_PATHS_H

#include "error.h"
#include "types.h"

#include <QtCore/QStringList>

namespace NetVfs::Paths {

// '/' separated; repeated separators collapse; trailing dropped; leading kept (absolute,
// backend-defined). "." and ".." components and NUL: InvalidName; lone surrogates (Names::decode
// escapes) accepted. Empty input = "" (backend base directory).
NETVFS_EXPORT Result normalize(const QString &path, QString *normalized);

NETVFS_EXPORT bool isAbsolute(const QString &normalizedPath);
NETVFS_EXPORT QStringList components(const QString &normalizedPath);
NETVFS_EXPORT QString join(const QString &dir, const QString &name);
NETVFS_EXPORT QString parent(const QString &normalizedPath);
NETVFS_EXPORT QString fileName(const QString &normalizedPath);

// Component must not contain \ : * ? " < >
// or end in space or dot. Empty = acceptable, else the reason.
NETVFS_EXPORT QString windowsComponentProblem(const QString &component);
NETVFS_EXPORT Result checkWindowsPath(const QString &normalizedPath);

// Proposes a name safe on a destination with these capabilities. '/' and NUL become '_'.
// WindowsNames: \ : * ? " < >
// and control chars become '_', trailing spaces/dots removed, reserved device names (CON, PRN, AUX,
// NUL, COM1-9, LPT1-9) get '_' after the stem. maxNameBytes > 0: UTF-8 truncated without splitting
// a code point, extension kept when it fits. Never empty, "." or "..".
NETVFS_EXPORT QString sanitizeFor(const Capabilities &capabilities, const QString &name);

}
#endif
