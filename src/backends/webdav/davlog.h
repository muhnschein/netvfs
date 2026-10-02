// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVLOG_H
#define NETVFS_DAVLOG_H

#include <QtCore/QLoggingCategory>

// "netvfs.webdav", default level warning (SPEC C-16). C-17/XSEC-5: host
// names, paths, hrefs and certificate subjects at debug level only.
Q_DECLARE_LOGGING_CATEGORY(lcNetVfsWebdav)

#endif
