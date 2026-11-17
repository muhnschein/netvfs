// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SECURE_H
#define NETVFS_SECURE_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace NetVfs {

// Overwrite secret material before release (best effort; detaches first so a shared copy is not
// left behind).
NETVFS_EXPORT void secureWipe(QByteArray &data);
NETVFS_EXPORT void secureWipe(QString &data);

}
#endif
