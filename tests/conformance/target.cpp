// SPDX-License-Identifier: LGPL-2.1-or-later
#include "target.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>

namespace Conformance {

namespace {

constexpr int DefaultConnectTimeoutMs = 15000;
constexpr int DefaultRequestTimeoutMs = 60000;
// The local targets give up waiting sooner, so that a broken cancel()
// fails the FIFO stall cases quickly instead of after a minute.
constexpr int LocalRequestTimeoutMs = 10000;

NetVfs::ConnectionParams paramsFrom(const QJsonObject &o, const NetVfs::ConnectionParams &base)
{
    NetVfs::ConnectionParams p = base;
    if (o.contains(QLatin1String("provider")))
        p.provider = o.value(QLatin1String("provider")).toString();
    if (o.contains(QLatin1String("host")))
        p.host = o.value(QLatin1String("host")).toString();
    if (o.contains(QLatin1String("port")))
        p.port = o.value(QLatin1String("port")).toInt();
    if (o.contains(QLatin1String("user")))
        p.username = o.value(QLatin1String("user")).toString();
    const QVariantMap options = o.value(QLatin1String("options")).toObject().toVariantMap();
    for (auto it = options.constBegin(); it != options.constEnd(); ++it)
        p.options.insert(it.key(), it.value());
    p.connectTimeoutMs = o.value(QLatin1String("connectTimeoutMs")).toInt(p.connectTimeoutMs);
    p.requestTimeoutMs = o.value(QLatin1String("requestTimeoutMs")).toInt(p.requestTimeoutMs);
    return p;
}

Target targetFrom(const QJsonObject &o)
{
    Target t;
    NetVfs::ConnectionParams defaults;
    defaults.connectTimeoutMs = DefaultConnectTimeoutMs;
    defaults.requestTimeoutMs = DefaultRequestTimeoutMs;
    t.params = paramsFrom(o, defaults);
    t.name = o.value(QLatin1String("name")).toString(t.params.provider);
    t.user = t.params.username;
    t.secretEnv = o.value(QLatin1String("secretEnv")).toString();
    t.trustOnFirstUse = o.value(QLatin1String("trustOnFirstUse")).toBool(false);
    t.baseDir = o.value(QLatin1String("baseDir")).toString();
    t.hostPath = o.value(QLatin1String("hostPath")).toString();
    t.listCount = o.value(QLatin1String("listCount")).toInt(t.listCount);
    t.fifoStall = o.value(QLatin1String("fifoStall")).toBool(t.params.provider == QLatin1String("local"))
        && !t.hostPath.isEmpty();
    t.restart = o.value(QLatin1String("restart")).toString();
    const QJsonObject skip = o.value(QLatin1String("skip")).toObject();
    for (auto it = skip.constBegin(); it != skip.constEnd(); ++it)
        t.skip.insert(it.key(), it.value().toString());
    const QJsonObject proxy = o.value(QLatin1String("stallProxy")).toObject();
    if (!proxy.isEmpty()) {
        t.stallProxy.enabled = true;
        t.stallProxy.params = paramsFrom(proxy, t.params);
        t.stallProxy.engage = proxy.value(QLatin1String("engage")).toString();
        t.stallProxy.release = proxy.value(QLatin1String("release")).toString();
    }
    return t;
}

QVector<Target> defaultTargets(const QString &scratch)
{
    // "local": root option, relative paths below it, NativeNoReplace where
    // the file system has it.
    Target relative;
    relative.name = QStringLiteral("local");
    relative.params.provider = QStringLiteral("local");
    relative.params.requestTimeoutMs = LocalRequestTimeoutMs;
    relative.params.options.insert(QStringLiteral("root"), scratch + QStringLiteral("/root"));
    relative.baseDir = QStringLiteral("conformance");
    relative.hostPath = scratch + QStringLiteral("/root/conformance");
    relative.fifoStall = true;
    QDir().mkpath(relative.hostPath);

    // "local-absolute": default root "/", absolute paths (L-1), and the
    // link()+unlink() / stat-check fallback of rename(NoReplace) (L-3).
    Target absolute;
    absolute.name = QStringLiteral("local-absolute");
    absolute.params.provider = QStringLiteral("local");
    absolute.params.requestTimeoutMs = LocalRequestTimeoutMs;
    absolute.params.options.insert(QStringLiteral("native_noreplace"), QStringLiteral("false"));
    absolute.baseDir = scratch + QStringLiteral("/absolute");
    absolute.hostPath = absolute.baseDir;
    absolute.fifoStall = true;
    QDir().mkpath(absolute.hostPath);
    return { relative, absolute };
}

} // namespace

bool loadTargets(const QString &scratch, QVector<Target> *out, QString *error)
{
    QVector<Target> targets;
    const QString config = QString::fromLocal8Bit(qgetenv("NETVFS_CONFORMANCE_CONFIG"));
    if (config.isEmpty()) {
        targets = defaultTargets(scratch);
    } else {
        QFile file(config);
        if (!file.open(QIODevice::ReadOnly)) {
            *error = QStringLiteral("Cannot read %1: %2").arg(config, file.errorString());
            return false;
        }
        QJsonParseError parseError {};
        const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
        if (doc.isNull()) {
            *error = QStringLiteral("%1: %2").arg(config, parseError.errorString());
            return false;
        }
        const QJsonArray list = doc.object().value(QLatin1String("targets")).toArray();
        for (const QJsonValue &value : list)
            targets.append(targetFrom(value.toObject()));
    }
    const QString only = QString::fromLocal8Bit(qgetenv("NETVFS_CONFORMANCE_TARGETS"));
    if (!only.isEmpty()) {
        const QStringList names = only.split(QLatin1Char(','), NETVFS_SKIP_EMPTY_PARTS);
        QVector<Target> selected;
        for (const Target &t : targets) {
            if (names.contains(t.name))
                selected.append(t);
        }
        targets = selected;
    }
    if (targets.isEmpty()) {
        *error = QStringLiteral("No conformance targets");
        return false;
    }
    *out = targets;
    return true;
}

Heavy heavyMode()
{
    const QByteArray value = qgetenv("NETVFS_CONFORMANCE_HEAVY");
    if (value == "0")
        return Heavy::Skip;
    if (value == "1")
        return Heavy::Always;
    return Heavy::Cheap;
}

} // namespace Conformance
