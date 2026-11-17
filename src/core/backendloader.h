// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BACKENDLOADER_H
#define NETVFS_BACKENDLOADER_H

#include "backend.h"
#include "sshkeys.h"

#include <QtCore/QStringList>

namespace NetVfs {

// Search directory: install location, overridable with NETVFS_BACKEND_PATH (colon separated) for
// tests.
class NETVFS_EXPORT BackendLoader
{
public:
    static QStringList searchPaths();
    // nullptr with `*result` set: Unsupported without a plugin, else the plugin's reason.
    static Backend *create(const QString &provider, Result *result = nullptr);
    static bool isAvailable(const QString &provider);
    static SshKeyTools *sshKeyTools();
};

}
#endif
