// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_BRIDGELOG_H
#define NETVFS_BRIDGE_BRIDGELOG_H

#include <QtCore/QLoggingCategory>

// SPEC-v2 XB-18: C-16 category "netvfs.bridge" (default level warning);
// C-17: no secrets at any level, paths, hosts and server text at debug only.
// Every line starts with the consumer id: qCWarning(lcNetVfsBridge).noquote()
// << consumerTag(id) << ...
Q_DECLARE_LOGGING_CATEGORY(lcNetVfsBridge)

namespace NetVfs::Bridge {
inline QString consumerTag(const QString &id)
{
    return QLatin1Char('[') + id + QLatin1Char(']');
}
} // namespace NetVfs::Bridge

#endif
