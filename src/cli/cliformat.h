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

namespace NetVfs::Cli {
QString sanitizeForTerminal(const QString &text);

QString modeString(const Entry &entry);
QString flagsString(EntryFlags flags);
QString isoTime(const QDateTime &time);
QString shortLine(const Entry &entry);
QString longLine(const Entry &entry, const QString &name = QString());
QJsonObject entryJson(const Entry &entry, const QString &name = QString());
QString jsonText(const QJsonObject &object);
QString jsonText(const QJsonArray &array);

QStringList capabilitiesLines(const Capabilities &capabilities);
QJsonObject capabilitiesJson(const Capabilities &capabilities);

QStringList identityLines(const ServerIdentity &identity);

struct ServiceView {
    DiscoveredService service;
    QStringList serviceTypes;
    QString url;
};
QVector<ServiceView> mergeServices(const QVector<DiscoveredService> &services);
QString serviceLine(const ServiceView &view);

}
#endif
