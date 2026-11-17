// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_NAMES_H
#define NETVFS_NAMES_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

// Lossless names: well-formed UTF-8 decodes normally; each byte b (0x80-0xFF) of an ill-formed
// sequence becomes lone surrogate U+DC00+b. encode() reverses exactly. Backends never
// QString::fromUtf8 remote names.
namespace NetVfs::Names {

NETVFS_EXPORT QString decode(const QByteArray &bytes);
NETVFS_EXPORT QByteArray encode(const QString &name);
NETVFS_EXPORT QString display(const QString &name);
// False if `name` holds a lone surrogate decode() cannot produce (e.g. unpaired UTF-16 from SMB):
// InvalidName for byte protocols.
NETVFS_EXPORT bool isEncodable(const QString &name);
NETVFS_EXPORT bool hasEscapes(const QString &name);

}
#endif
