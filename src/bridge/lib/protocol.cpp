// SPDX-License-Identifier: LGPL-2.1-or-later
#include "protocol.h"

#include "names.h"

#include <QtCore/QFile>

#include <dbus/dbus.h>

#ifndef NETVFS_BRIDGE_VERSION
#define NETVFS_BRIDGE_VERSION "0.2.0"
#endif

static void initBridgeResources()
{
    Q_INIT_RESOURCE(bridge);
}

namespace NetVfs {
namespace Bridge {
namespace Protocol {

QString bridgeVersion()
{
    return QStringLiteral(NETVFS_BRIDGE_VERSION);
}

QStringList features()
{
    // "error-details": error replies carry a second argument a{sv} with
    // "detail" and "retryAfterMs" (XC-24, XB-17).
    return QStringList() << QStringLiteral("error-details");
}

QString introspectionXml()
{
    static const QString xml = []() {
        initBridgeResources();
        QFile file(QStringLiteral(":/netvfs-bridge/org.netvfs.Bridge1.xml"));
        if (!file.open(QIODevice::ReadOnly))
            return QString();
        return QString::fromUtf8(file.readAll());
    }();
    return xml;
}

QString errorNameFor(const Result &result, bool fromValidation)
{
    if (fromValidation && result.error() == Error::ProtocolError)
        return QLatin1String(InvalidArgsError);
    if (fromValidation && result.error() == Error::Unsupported)
        return QLatin1String(UnknownMethodError);
    return QLatin1String(ErrorPrefix) + errorName(result.ok() ? Error::Internal : result.error());
}

qint64 toMs(const QDateTime &time)
{
    return time.isValid() ? time.toMSecsSinceEpoch() : -1;
}

void writeEntry(WireWriter &writer, const Entry &entry)
{
    writer.openStruct()
        .bytes(Names::encode(entry.name))
        .byte(static_cast<quint8>(entry.type))
        .byte(static_cast<quint8>(entry.targetType))
        .int64(entry.size)
        .int64(toMs(entry.modified))
        .int64(toMs(entry.created))
        .int64(toMs(entry.accessed))
        .int32(entry.mode)
        .int64(entry.uid)
        .int64(entry.gid)
        .string(entry.owner)
        .string(entry.group)
        .uint16(static_cast<quint16>(entry.flags))
        .bytes(entry.etag)
        .string(entry.contentType)
        .close();
}

void writeCapabilities(WireWriter &writer, const Capabilities &capabilities)
{
    writer.openStruct()
        .strings(capabilities.names())
        .strings(capabilities.checksumAlgorithms)
        .int64(capabilities.maxNameBytes)
        .close();
}

MessagePtr methodReturn(DBusMessage *call)
{
    return MessagePtr(dbus_message_new_method_return(call));
}

MessagePtr errorReply(DBusMessage *call, const QString &name, const Result &result)
{
    const QByteArray errorName = name.toUtf8();
    MessagePtr reply(dbus_message_new_error(call, errorName.constData(), nullptr));
    if (!reply)
        return reply;
    WireWriter writer(reply.get());
    const QString shortName = name.mid(name.lastIndexOf(QLatin1Char('.')) + 1);
    writer.string(result.message().isEmpty() ? shortName : result.message());
    QVariantMap extra;
    if (!result.detail().isEmpty())
        extra.insert(QStringLiteral("detail"), result.detail());
    if (result.retryAfterMs() >= 0)
        extra.insert(QStringLiteral("retryAfterMs"), result.retryAfterMs());
    if (!extra.isEmpty())
        writer.variantMap(extra);
    if (!writer.ok())
        return MessagePtr();
    return reply;
}

MessagePtr signal(const char *member)
{
    return MessagePtr(dbus_message_new_signal(ObjectPath, Interface, member));
}

} // namespace Protocol
} // namespace Bridge
} // namespace NetVfs
