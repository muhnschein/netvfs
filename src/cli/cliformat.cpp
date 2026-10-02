// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cliformat.h"

#include "names.h"
#include "url.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonValue>
#include <QtCore/QMap>

#include <array>

namespace NetVfs::Cli {

namespace {

const qint32 ModeSetUid = 04000;
const qint32 ModeSetGid = 02000;
const qint32 ModeSticky = 01000;
const qint32 ModeMask = 07777;
const int PermissionBits = 9;
const ushort FirstPrintable = 0x20;
const ushort Delete = 0x7f;
const ushort FirstC1 = 0x80;
const ushort LastC1 = 0x9f;

QChar typeChar(EntryType type)
{
    switch (type) {
    case EntryType::File:
        return QLatin1Char('-');
    case EntryType::Directory:
        return QLatin1Char('d');
    case EntryType::Symlink:
        return QLatin1Char('l');
    case EntryType::Special:
        return QLatin1Char('s');
    case EntryType::Unknown:
        break;
    }
    return QLatin1Char('?');
}

QString typeName(EntryType type)
{
    switch (type) {
    case EntryType::File:
        return QStringLiteral("file");
    case EntryType::Directory:
        return QStringLiteral("directory");
    case EntryType::Symlink:
        return QStringLiteral("symlink");
    case EntryType::Special:
        return QStringLiteral("special");
    case EntryType::Unknown:
        break;
    }
    return QStringLiteral("unknown");
}

// rwx triplet for `shift` (6 owner, 3 group, 0 other); `special` is the
// setuid/setgid/sticky bit that replaces the x column ('s' or 't').
QString triplet(qint32 mode, int shift, bool special, QChar specialChar)
{
    const qint32 bits = (mode >> shift) & 07;
    QString text(3, QLatin1Char('-'));
    if (bits & 04)
        text[0] = QLatin1Char('r');
    if (bits & 02)
        text[1] = QLatin1Char('w');
    const bool execute = (bits & 01) != 0;
    if (special)
        text[2] = execute ? specialChar : specialChar.toUpper();
    else if (execute)
        text[2] = QLatin1Char('x');
    return text;
}

QString principal(const QString &name, qint64 id)
{
    if (!name.isEmpty())
        return sanitizeForTerminal(name);
    return id >= 0 ? QString::number(id) : QStringLiteral("-");
}

QJsonValue textOrNull(const QString &text)
{
    return text.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(text);
}

QJsonValue numberOrNull(qint64 value)
{
    return value < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(static_cast<double>(value));
}

QJsonValue timeOrNull(const QDateTime &time)
{
    return time.isValid() ? QJsonValue(time.toUTC().toString(Qt::ISODate)) : QJsonValue(QJsonValue::Null);
}

QJsonArray flagNames(EntryFlags flags)
{
    struct Flag {
        EntryFlag flag;
        const char *name;
    };
    static const std::array<Flag, 5> table = { {
        { EntryFlag::Hidden, "hidden" }, { EntryFlag::ReadOnly, "readOnly" }, { EntryFlag::System, "system" },
        { EntryFlag::NameNotUtf8, "nameNotUtf8" }, { EntryFlag::TargetUnknown, "targetUnknown" },
    } };
    QJsonArray names;
    for (const Flag &entry : table) {
        if (flags.testFlag(entry.flag))
            names.append(QLatin1String(entry.name));
    }
    return names;
}

QString problemNames(int problems)
{
    struct Problem {
        int bit;
        const char *name;
    };
    static const std::array<Problem, 5> table = { {
        { ServerIdentity::SelfSigned, "self-signed" }, { ServerIdentity::UntrustedRoot, "untrusted-root" },
        { ServerIdentity::Expired, "expired" }, { ServerIdentity::NotYetValid, "not-yet-valid" },
        { ServerIdentity::HostnameMismatch, "hostname-mismatch" },
    } };
    QStringList names;
    for (const Problem &entry : table) {
        if (problems & entry.bit)
            names << QLatin1String(entry.name);
    }
    return names.join(QLatin1Char(' '));
}

QStringList tlsLines(const ServerIdentity &identity)
{
    QStringList lines;
    lines << QStringLiteral("system-trusted: ") + (identity.systemTrusted ? QStringLiteral("yes") : QStringLiteral("no"));
    if (identity.problems != 0)
        lines << QStringLiteral("problems: ") + problemNames(identity.problems);
    struct Detail {
        const char *key;
        const char *label;
    };
    static const std::array<Detail, 6> details = { {
        { "subject", "subject" }, { "issuer", "issuer" }, { "notBefore", "not-before" },
        { "notAfter", "not-after" }, { "sans", "sans" }, { "certSha256", "cert-sha256" },
    } };
    for (const Detail &detail : details) {
        const QVariant value = identity.details.value(QLatin1String(detail.key));
        if (value.isValid()) {
            lines << QLatin1String(detail.label) + QStringLiteral(": ")
                    + sanitizeForTerminal(value.toStringList().join(QStringLiteral(", ")));
        }
    }
    // W-4: tls_verify_peer records whether the pinned certificate was system trusted.
    if (identity.systemTrusted) {
        lines << QStringLiteral("advice: pin it with --host-key and add --option tls_verify_peer=true to keep "
                                "chain and host name verification; public CAs rotate keys, so the pin may "
                                "need updating");
    } else {
        lines << QStringLiteral("advice: pin it with --host-key and leave tls_verify_peer unset: the pin alone "
                                "is relied upon, chain and host name are not verified");
    }
    return lines;
}

QString sanitizeField(const QString &text)
{
    QString clean = text;
    clean.replace(QLatin1Char('\t'), QLatin1Char(' '));
    return sanitizeForTerminal(clean);
}

} // namespace

QString sanitizeForTerminal(const QString &text)
{
    QString clean = text;
    for (QChar &c : clean) {
        if (c.unicode() < FirstPrintable || c.unicode() == Delete || (c.unicode() >= FirstC1 && c.unicode() <= LastC1))
            c = QLatin1Char('?');
    }
    return clean;
}

QString modeString(const Entry &entry)
{
    QString text(1, typeChar(entry.type));
    if (entry.mode < 0)
        return text + QString(PermissionBits, QLatin1Char('?'));
    const qint32 mode = entry.mode & ModeMask;
    return text + triplet(mode, 6, (mode & ModeSetUid) != 0, QLatin1Char('s'))
        + triplet(mode, 3, (mode & ModeSetGid) != 0, QLatin1Char('s'))
        + triplet(mode, 0, (mode & ModeSticky) != 0, QLatin1Char('t'));
}

QString flagsString(EntryFlags flags)
{
    QString text;
    if (flags.testFlag(EntryFlag::Hidden))
        text += QLatin1Char('H');
    if (flags.testFlag(EntryFlag::ReadOnly))
        text += QLatin1Char('R');
    if (flags.testFlag(EntryFlag::System))
        text += QLatin1Char('S');
    if (flags.testFlag(EntryFlag::NameNotUtf8))
        text += QLatin1Char('N');
    if (flags.testFlag(EntryFlag::TargetUnknown))
        text += QLatin1Char('T');
    return text.isEmpty() ? QStringLiteral("-") : text;
}

QString isoTime(const QDateTime &time)
{
    return time.isValid() ? time.toUTC().toString(Qt::ISODate) : QStringLiteral("-");
}

QString shortLine(const Entry &entry)
{
    // A symlink to a folder shows as "d" (isDir() follows targetType), as in v1.
    const QChar type = entry.isDir() ? QLatin1Char('d') : typeChar(entry.type);
    return QString(type) + QLatin1Char(' ') + QString::number(entry.size) + QLatin1Char(' ')
        + sanitizeForTerminal(Names::display(entry.name));
}

QString longLine(const Entry &entry, const QString &name)
{
    const QString shown = name.isEmpty() ? entry.name : name;
    const QString size = entry.size < 0 ? QStringLiteral("-") : QString::number(entry.size);
    return modeString(entry) + QLatin1Char(' ') + principal(entry.owner, entry.uid) + QLatin1Char(' ')
        + principal(entry.group, entry.gid) + QLatin1Char(' ') + size + QLatin1Char(' ') + isoTime(entry.modified)
        + QLatin1Char(' ') + flagsString(entry.flags) + QLatin1Char(' ')
        + sanitizeForTerminal(Names::display(shown));
}

QJsonObject entryJson(const Entry &entry, const QString &name)
{
    const QString shown = name.isEmpty() ? entry.name : name;
    QJsonObject object;
    object.insert(QStringLiteral("name"), Names::display(shown));
    if (entry.flags.testFlag(EntryFlag::NameNotUtf8) || Names::hasEscapes(shown))
        object.insert(QStringLiteral("nameBytes"), QString::fromLatin1(Names::encode(shown).toBase64()));
    object.insert(QStringLiteral("type"), typeName(entry.type));
    if (entry.type == EntryType::Symlink)
        object.insert(QStringLiteral("targetType"), typeName(entry.targetType));
    object.insert(QStringLiteral("size"), numberOrNull(entry.size));
    object.insert(QStringLiteral("mode"), numberOrNull(entry.mode < 0 ? -1 : entry.mode & ModeMask));
    object.insert(QStringLiteral("uid"), numberOrNull(entry.uid));
    object.insert(QStringLiteral("gid"), numberOrNull(entry.gid));
    object.insert(QStringLiteral("owner"), textOrNull(entry.owner));
    object.insert(QStringLiteral("group"), textOrNull(entry.group));
    object.insert(QStringLiteral("modified"), timeOrNull(entry.modified));
    object.insert(QStringLiteral("created"), timeOrNull(entry.created));
    object.insert(QStringLiteral("accessed"), timeOrNull(entry.accessed));
    object.insert(QStringLiteral("flags"), flagNames(entry.flags));
    if (!entry.etag.isEmpty())
        object.insert(QStringLiteral("etag"), QString::fromLatin1(entry.etag.toBase64()));
    if (!entry.contentType.isEmpty())
        object.insert(QStringLiteral("contentType"), entry.contentType);
    if (!entry.extra.isEmpty())
        object.insert(QStringLiteral("extra"), QJsonObject::fromVariantMap(entry.extra));
    return object;
}

QString jsonText(const QJsonObject &object)
{
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented));
}

QString jsonText(const QJsonArray &array)
{
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Indented));
}

QStringList capabilitiesLines(const Capabilities &capabilities)
{
    QStringList lines;
    lines << QStringLiteral("capabilities: ") + capabilities.names().join(QLatin1Char(' '));
    lines << QStringLiteral("checksums: ") + capabilities.checksumAlgorithms.join(QLatin1Char(' '));
    lines << QStringLiteral("maxNameBytes: ")
            + (capabilities.maxNameBytes < 0 ? QStringLiteral("unknown") : QString::number(capabilities.maxNameBytes));
    lines << QStringLiteral("maxReadChunk: ")
            + (capabilities.maxReadChunk <= 0 ? QStringLiteral("unknown") : QString::number(capabilities.maxReadChunk));
    lines << QStringLiteral("maxWriteChunk: ")
            + (capabilities.maxWriteChunk <= 0 ? QStringLiteral("unknown") : QString::number(capabilities.maxWriteChunk));
    return lines;
}

QJsonObject capabilitiesJson(const Capabilities &capabilities)
{
    QJsonObject object;
    object.insert(QStringLiteral("capabilities"), QJsonArray::fromStringList(capabilities.names()));
    object.insert(QStringLiteral("checksums"), QJsonArray::fromStringList(capabilities.checksumAlgorithms));
    object.insert(QStringLiteral("maxNameBytes"), numberOrNull(capabilities.maxNameBytes));
    object.insert(QStringLiteral("maxReadChunk"), numberOrNull(capabilities.maxReadChunk > 0 ? capabilities.maxReadChunk : -1));
    object.insert(QStringLiteral("maxWriteChunk"),
                  numberOrNull(capabilities.maxWriteChunk > 0 ? capabilities.maxWriteChunk : -1));
    return object;
}

QStringList identityLines(const ServerIdentity &identity)
{
    QStringList lines;
    lines << identity.fingerprint << identity.toPin();
    if (identity.kind == ServerIdentity::Kind::TlsCertificate)
        lines << tlsLines(identity);
    return lines;
}

QVector<ServiceView> mergeServices(const QVector<DiscoveredService> &services)
{
    QMap<QString, ServiceView> byEndpoint;
    for (const DiscoveredService &service : services) {
        const QString key = service.endpointKey();
        auto it = byEndpoint.find(key);
        if (it == byEndpoint.end()) {
            ServiceView view;
            view.service = service;
            QString path;
            const ConnectionParams params = toConnectionParams(service, &path);
            view.url = Url::format(params, path);
            it = byEndpoint.insert(key, view);
        }
        if (!it->serviceTypes.contains(service.serviceType))
            it->serviceTypes << service.serviceType;
    }
    QVector<ServiceView> merged;
    for (ServiceView view : byEndpoint) {
        view.serviceTypes.sort();
        merged.append(view);
    }
    return merged;
}

QString serviceLine(const ServiceView &view)
{
    QStringList addresses;
    for (const QHostAddress &address : view.service.addresses)
        addresses << address.toString();
    return sanitizeField(view.url) + QLatin1Char('\t') + sanitizeField(view.service.instanceName) + QLatin1Char('\t')
        + sanitizeField(view.serviceTypes.join(QLatin1Char(','))) + QLatin1Char('\t')
        + sanitizeField(addresses.join(QLatin1Char(',')));
}

} // namespace NetVfs::Cli
