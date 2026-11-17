// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOGGING_H
#define NETVFS_LOGGING_H

#include "netvfs_global.h"

#include <QtCore/QLoggingCategory>

// Never log secrets, keys or SMB challenge material; host names, user names, remote paths at debug
// level only.
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsCore)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsSftp)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsSmb)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsButeo)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsUi)

#endif
