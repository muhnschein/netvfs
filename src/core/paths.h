// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_PATHS_H
#define NETVFS_PATHS_H

#include "error.h"
#include "types.h"

#include <QtCore/QStringList>

namespace NetVfs::Paths {

// SPEC C-15. '/' separated; repeated separators collapse; a trailing separator
// is dropped; a leading separator is kept (absolute path, backend-defined
// meaning). Components "." and "..", and NUL characters, are rejected with
// InvalidName; lone surrogates (Names::decode escapes, XC-4) are accepted.
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

// SPEC-v2 XH-7: proposes a name that is safe to create on a destination with
// these capabilities, for example when copying "a:b.txt" to an SMB share.
// '/' and NUL become '_'. With WindowsNames: \ : * ? " < > | and control
// characters become '_', trailing spaces and dots are removed, and reserved
// device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without an
// extension) get a '_' appended to the stem. With maxNameBytes > 0 the UTF-8
// encoding (Names::encode) is truncated to that many bytes without splitting a
// code point, keeping the extension when it fits. Never returns an empty
// string, "." or "..".
NETVFS_EXPORT QString sanitizeFor(const Capabilities &capabilities, const QString &name);

} // namespace NetVfs::Paths

#endif
