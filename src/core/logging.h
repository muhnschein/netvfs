// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOGGING_H
#define NETVFS_LOGGING_H

#include "netvfs_global.h"

#include <QtCore/QLoggingCategory>

// SPEC C-16: categories, default level warning.
// SPEC C-17: never log secrets, keys or SMB challenge material; host names,
// user names and remote paths at debug level only.
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsCore)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsSftp)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsSmb)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsButeo)
NETVFS_EXPORT Q_DECLARE_LOGGING_CATEGORY(lcNetVfsUi)

#endif
