// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_GLOBAL_H
#define NETVFS_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(NETVFS_BUILD_CORE)
#  define NETVFS_EXPORT Q_DECL_EXPORT
#else
#  define NETVFS_EXPORT Q_DECL_IMPORT
#endif

// Qt 5.6 (the target) only has QString::SkipEmptyParts; Qt >= 5.14 deprecates it.
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
#  define NETVFS_SKIP_EMPTY_PARTS Qt::SkipEmptyParts
#else
#  define NETVFS_SKIP_EMPTY_PARTS QString::SkipEmptyParts
#endif

#endif
