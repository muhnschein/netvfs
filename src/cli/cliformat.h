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

// Names rendered with Names::display() in text; JSON carries the display name and, for escaped
// bytes, "nameBytes" in base64. Server text is stripped of control characters before it reaches the
// terminal.
namespace NetVfs::Cli {

// Control characters (terminal escape sequences) become '?'.
QString sanitizeForTerminal(const QString &text);

QString modeString(const Entry &entry);
QString flagsString(EntryFlags flags);
QString isoTime(const QDateTime &time);
QString shortLine(const Entry &entry);
// "<mode> <owner> <group> <size> <mtime> <flags> <name>"; owner/group names, else numeric ids, else
// "-". `name` replaces entry.name when not empty.
QString longLine(const Entry &entry, const QString &name = QString());
// Machine-readable entry: name, [nameBytes], type, [targetType], size, mode, uid, gid, owner,
// group, modified, created, accessed, flags, [etag], [contentType], [extra]. Unknown values are
// null.
QJsonObject entryJson(const Entry &entry, const QString &name = QString());
QString jsonText(const QJsonObject &object);
QString jsonText(const QJsonArray &array);

QStringList capabilitiesLines(const Capabilities &capabilities);
QJsonObject capabilitiesJson(const Capabilities &capabilities);

QStringList identityLines(const ServerIdentity &identity);

// Services of one endpoint (provider, host, port) merged: one machine announcing _ssh._tcp and
// _sftp-ssh._tcp shows up once.
struct ServiceView {
    DiscoveredService service;
    QStringList serviceTypes;
    QString url;
};
QVector<ServiceView> mergeServices(const QVector<DiscoveredService> &services);
// "<url>\t<instance>\t<service types>\t<addresses>" (tabs inside fields become spaces).
QString serviceLine(const ServiceView &view);

}
#endif
