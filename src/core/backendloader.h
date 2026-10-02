// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BACKENDLOADER_H
#define NETVFS_BACKENDLOADER_H

#include "backend.h"

#include <QtCore/QStringList>

namespace NetVfs {

// Locates backend plugins (SPEC C-3). The search directory is the install
// location, overridable with NETVFS_BACKEND_PATH (colon separated) for tests.
class NETVFS_EXPORT BackendLoader
{
public:
    static QStringList searchPaths();
    // Returns a new backend for `provider`, or nullptr with `*result` set.
    static Backend *create(const QString &provider, Result *result = nullptr);
    static bool isAvailable(const QString &provider);
};

} // namespace NetVfs

#endif
