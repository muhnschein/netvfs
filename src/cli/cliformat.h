// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CLI_FORMAT_H
#define NETVFS_CLI_FORMAT_H

#include "discovery.h"
#include "types.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVector>

// Output formatting of netvfs-cli (SPEC-v2 XC-CLI). Names are rendered with
// Names::display() in text output; JSON carries the display name and, when
// the name holds escaped bytes (XC-4), "nameBytes" with the raw bytes in
// base64. Text coming from servers (certificates, service names) is stripped
// of control characters before it reaches the terminal.
namespace NetVfs::Cli {

// Replaces control characters (terminal escape sequences) by '?'.
QString sanitizeForTerminal(const QString &text);

// "-rw-r--r--": entry type, then the permission bits; "?" for unknown modes.
QString modeString(const Entry &entry);
// "HRSNT" letters of the set flags, "-" for none.
QString flagsString(EntryFlags flags);
// ISO 8601 UTC ("2024-01-02T03:04:05Z"), "-" for an invalid time.
QString isoTime(const QDateTime &time);
// "<d|-|l|s|?> <size> <name>": the plain `ls` line (size -1 when unknown).
QString shortLine(const Entry &entry);
// "<mode> <owner> <group> <size> <mtime> <flags> <name>"; owner and group are
// names, else numeric ids, else "-". `name` replaces entry.name when not empty
// (stat prints the path it was given).
QString longLine(const Entry &entry, const QString &name = QString());
// The machine-readable form of an entry: name, [nameBytes], type,
// [targetType], size, mode, uid, gid, owner, group, modified, created,
// accessed, flags, [etag], [contentType], [extra]. Unknown values are null.
QJsonObject entryJson(const Entry &entry, const QString &name = QString());
QString jsonText(const QJsonObject &object);
QString jsonText(const QJsonArray &array);

// `caps`: "key: value" lines, and the same as JSON.
QStringList capabilitiesLines(const Capabilities &capabilities);
QJsonObject capabilitiesJson(const Capabilities &capabilities);

// TLS and SSH identity as printed by `identify`; the first two lines are the
// fingerprint and the pin for every kind.
QStringList identityLines(const ServerIdentity &identity);

// `discover`: services of one endpoint (provider, host, port) merged, so a
// machine announcing _ssh._tcp and _sftp-ssh._tcp shows up once.
struct ServiceView {
    DiscoveredService service;
    QStringList serviceTypes;       // sorted
    QString url;                    // Url::format() of the connection template; empty if none
};
QVector<ServiceView> mergeServices(const QVector<DiscoveredService> &services);
// "<url>\t<instance>\t<service types>\t<addresses>" (tabs inside fields become spaces).
QString serviceLine(const ServiceView &view);

} // namespace NetVfs::Cli

#endif
