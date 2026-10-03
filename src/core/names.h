// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_NAMES_H
#define NETVFS_NAMES_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

// SPEC-v2 XC-4: lossless names. Server bytes are decoded with a reversible
// "surrogate escape" codec: well-formed UTF-8 decodes normally; every byte b
// (0x80-0xFF) of an ill-formed sequence becomes the lone surrogate U+DC00+b.
// encode() reverses this exactly. No backend calls QString::fromUtf8 on
// remote names.
namespace NetVfs::Names {

NETVFS_EXPORT QString decode(const QByteArray &bytes);
NETVFS_EXPORT QByteArray encode(const QString &name);
// Escapes rendered as U+FFFD, for display only.
NETVFS_EXPORT QString display(const QString &name);
// False if `name` holds a lone surrogate that decode() cannot produce (for
// example an unpaired UTF-16 surrogate from an SMB server); such names are
// InvalidName for byte-oriented protocols.
NETVFS_EXPORT bool isEncodable(const QString &name);
// True if `name` contains escaped bytes (EntryFlag::NameNotUtf8).
NETVFS_EXPORT bool hasEscapes(const QString &name);

} // namespace NetVfs::Names

#endif
