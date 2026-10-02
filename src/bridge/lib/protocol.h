// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_PROTOCOL_H
#define NETVFS_BRIDGE_PROTOCOL_H

#include "error.h"
#include "types.h"
#include "wire.h"

#include <QtCore/QString>

// SPEC-v2 XB-8, XB-9: names, types and message construction of
// org.netvfs.Bridge1.
namespace NetVfs {
namespace Bridge {
namespace Protocol {

constexpr quint32 Version = 1;
constexpr const char *ObjectPath = "/org/netvfs/Bridge";
constexpr const char *Interface = "org.netvfs.Bridge1";
constexpr const char *ErrorPrefix = "org.netvfs.Error.";
constexpr const char *InvalidArgsError = "org.freedesktop.DBus.Error.InvalidArgs";
constexpr const char *UnknownMethodError = "org.freedesktop.DBus.Error.UnknownMethod";
constexpr const char *EntrySignature = "(ayyyxxxxixxssqays)";

QString bridgeVersion();
// Feature strings announced by Hello (XB-8: additive changes add one).
QStringList features();

// The introspection XML (the contract, org.netvfs.Bridge1.xml).
QString introspectionXml();

// "org.netvfs.Error.NotFound"; ProtocolError from argument validation maps
// to org.freedesktop.DBus.Error.InvalidArgs.
QString errorNameFor(const Result &result, bool fromValidation);

// Milliseconds since the epoch, -1 for an invalid time.
qint64 toMs(const QDateTime &time);

// Appends the Entry struct.
void writeEntry(WireWriter &writer, const Entry &entry);
// Appends (as flags, as checksumAlgorithms, x maxNameBytes).
void writeCapabilities(WireWriter &writer, const Capabilities &capabilities);

// Message factories (nullptr on out-of-memory).
MessagePtr methodReturn(DBusMessage *call);
// Error reply: message as first argument, then a{sv} with "detail" and
// "retryAfterMs" when the result has them.
MessagePtr errorReply(DBusMessage *call, const QString &name, const Result &result);
MessagePtr signal(const char *member);

} // namespace Protocol
} // namespace Bridge
} // namespace NetVfs

#endif
