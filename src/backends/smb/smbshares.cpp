// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbshares.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>
#include <QtCore/QList>
#include <QtCore/QStringList>
#include <QtCore/QtEndian>

#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>

namespace NetVfs::Smb {

namespace {

const int FieldCount = 7;
const int LengthBytes = 4;
const int MaxShareNameLength = 80;          // NNLEN
const double MaxShareType = 4294967295.0;

void appendField(QByteArray *out, const QByteArray &field)
{
    std::array<uchar, LengthBytes> length = {};
    qToBigEndian(static_cast<quint32>(field.size()), length.data());
    out->append(reinterpret_cast<const char *>(length.data()), LengthBytes);
    out->append(field);
}

bool takeField(const QByteArray &data, int *at, QByteArray *field)
{
    if (data.size() - *at < LengthBytes)
        return false;
    const quint32 length = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + *at));
    *at += LengthBytes;
    if (length > static_cast<quint32>(data.size() - *at))
        return false;
    *field = data.mid(*at, static_cast<int>(length));
    *at += static_cast<int>(length);
    return true;
}

bool parseTimeout(const QByteArray &text, int *out)
{
    // Canonical decimal only: no sign, no leading zero.
    if (text.isEmpty() || text.size() > 9 || (text.size() > 1 && text.at(0) == '0'))
        return false;
    for (const char c : text) {
        if (c < '0' || c > '9')
            return false;
    }
    *out = text.toInt();
    return true;
}

Result malformed(const QString &what)
{
    return Result(Error::ProtocolError, QStringLiteral("the share list helper's output is malformed: %1").arg(what));
}

// Errors the helper may report as such: they describe the server, the
// network or the account. Anything else it claims is a protocol error.
bool passesThrough(Error error)
{
    switch (error) {
    case Error::AuthFailed:
    case Error::SecurityPolicy:
    case Error::NetworkUnreachable:
    case Error::Timeout:
    case Error::PermissionDenied:
    case Error::NotFound:
    case Error::Unsupported:
    case Error::ProtocolError:
    case Error::ConnectionLost:
    case Error::TooManyConnections:
        return true;
    default:
        return false;
    }
}

QString cleanText(const QString &text, int maxLength)
{
    const QString head = text.left(maxLength);
    QString clean;
    std::copy_if(head.begin(), head.end(), std::back_inserter(clean),
                 [](QChar c) { return c.unicode() >= 0x20 && c.unicode() != 0x7f; });
    return clean;
}

bool hasOnlyKeys(const QJsonObject &object, const QStringList &keys)
{
    // Missing keys are caught by the type checks of the callers.
    const QStringList present = object.keys();
    return std::all_of(present.begin(), present.end(), [&keys](const QString &key) { return keys.contains(key); });
}

Result parseShare(const QJsonObject &object, ShareInfo *share)
{
    if (!hasOnlyKeys(object, { QStringLiteral("name"), QStringLiteral("type"), QStringLiteral("remark") }))
        return malformed(QStringLiteral("unexpected fields in a share"));
    const QJsonValue name = object.value(QStringLiteral("name"));
    const QJsonValue type = object.value(QStringLiteral("type"));
    const QJsonValue remark = object.value(QStringLiteral("remark"));
    if (!name.isString() || !type.isDouble() || !remark.isString())
        return malformed(QStringLiteral("a share field has the wrong type"));
    const double number = type.toDouble();
    if (!(number >= 0 && number <= MaxShareType) || std::floor(number) != number)
        return malformed(QStringLiteral("a share type is out of range"));
    if (!validShareName(name.toString()))
        return malformed(QStringLiteral("a share name is not valid"));
    share->name = name.toString();
    share->type = static_cast<quint32>(number);
    share->remark = cleanText(remark.toString(), MaxRemarkLength);
    return Result::success();
}

Result parseError(const QJsonObject &object)
{
    if (!hasOnlyKeys(object, { QStringLiteral("error"), QStringLiteral("message") }))
        return malformed(QStringLiteral("unexpected fields in an error"));
    const QJsonValue name = object.value(QStringLiteral("error"));
    const QJsonValue message = object.value(QStringLiteral("message"));
    if (!name.isString() || !message.isString())
        return malformed(QStringLiteral("an error field has the wrong type"));
    const Error error = errorFromName(name.toString());
    const QString text = cleanText(message.toString(), MaxHelperMessageLength);
    if (error == Error::None || !passesThrough(error))
        return malformed(QStringLiteral("an unexpected error"));
    return Result(error, text);
}

Result parseEnd(const QJsonObject &object, int count)
{
    if (const QJsonValue end = object.value(QStringLiteral("end"));
        object.size() != 1 || !end.isDouble() || end.toDouble() != count)
        return malformed(QStringLiteral("the share count does not match"));
    return Result::success();
}

// The lines of `output` when it ends in a newline and no line is too long.
Result splitLines(const QByteArray &output, QList<QByteArray> *lines)
{
    if (output.size() > MaxShareOutputBytes)
        return malformed(QStringLiteral("too much output"));
    if (!output.endsWith('\n'))
        return malformed(QStringLiteral("the output is truncated"));
    *lines = output.left(output.size() - 1).split('\n');
    for (const QByteArray &line : *lines) {
        if (line.size() > MaxShareLineBytes)
            return malformed(QStringLiteral("a line is too long"));
    }
    if (lines->size() > MaxShares + 1)
        return malformed(QStringLiteral("too many shares"));
    return Result::success();
}

} // namespace

bool validShareName(const QString &name)
{
    if (name.isEmpty() || name.size() > MaxShareNameLength || name == QLatin1String(".")
        || name == QLatin1String(".."))
        return false;
    // Windows refuses these in share names; ',' also separates the
    // account option "shares".
    const QString forbidden = QStringLiteral("/\\:*?\"<>|[]+=;,");
    return std::none_of(name.begin(), name.end(), [&forbidden](QChar c) {
        return c.unicode() < 0x20 || c.unicode() == 0x7f || c.isSurrogate() || forbidden.contains(c);
    });
}

QByteArray encodeShareRequest(const ShareRequest &request)
{
    const QByteArray timeout = QByteArray::number(request.requestTimeoutMs);
    QByteArray out;
    // One allocation: no copy of the secret is left behind by growing (XSEC-6).
    out.reserve(FieldCount * LengthBytes + static_cast<int>(qstrlen(ShareRequestMagic)) + request.server.size()
                + request.user.size() + request.domain.size() + request.profile.size() + timeout.size()
                + request.secret.size());
    appendField(&out, QByteArray(ShareRequestMagic));
    appendField(&out, request.server);
    appendField(&out, request.user);
    appendField(&out, request.domain);
    appendField(&out, request.profile);
    appendField(&out, timeout);
    appendField(&out, request.secret);
    return out;
}

bool decodeShareRequest(const QByteArray &data, ShareRequest *out)
{
    if (data.size() > MaxShareRequestBytes)
        return false;
    std::array<QByteArray, FieldCount> fields;
    int at = 0;
    for (QByteArray &field : fields) {
        if (!takeField(data, &at, &field))
            return false;
    }
    int timeout = 0;
    if (at != data.size() || fields[0] != ShareRequestMagic || fields[1].isEmpty() || !parseTimeout(fields[5], &timeout))
        return false;
    out->server = fields[1];
    out->user = fields[2];
    out->domain = fields[3];
    out->profile = fields[4];
    out->requestTimeoutMs = timeout;
    out->secret = fields[6];
    return true;
}

QByteArray shareLine(const ShareInfo &share)
{
    QJsonObject object;
    object.insert(QStringLiteral("name"), share.name);
    object.insert(QStringLiteral("type"), static_cast<double>(share.type));
    object.insert(QStringLiteral("remark"), share.remark);
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QByteArray endLine(int count)
{
    QJsonObject object;
    object.insert(QStringLiteral("end"), count);
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QByteArray errorLine(const Result &result)
{
    QJsonObject object;
    object.insert(QStringLiteral("error"), errorName(result.error()));
    object.insert(QStringLiteral("message"), result.message().left(MaxHelperMessageLength));
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

namespace {

Result parseLines(const QList<QByteArray> &lines, QVector<ShareInfo> *shares)
{
    QStringList seen;
    int count = 0;
    for (int i = 0; i < lines.size(); ++i) {
        QJsonParseError error {};
        const QJsonDocument document = QJsonDocument::fromJson(lines.at(i), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject())
            return malformed(QStringLiteral("a line is not a JSON object"));
        const QJsonObject object = document.object();
        const bool last = i == lines.size() - 1;
        if (object.contains(QStringLiteral("error")))
            return last ? parseError(object) : malformed(QStringLiteral("output after an error"));
        if (object.contains(QStringLiteral("end")))
            return last ? parseEnd(object, count) : malformed(QStringLiteral("output after the end"));
        ShareInfo share;
        if (Result r = parseShare(object, &share); !r.ok())
            return r;
        ++count;
        if (!seen.contains(share.name, Qt::CaseInsensitive)) {
            seen.append(share.name);
            shares->append(share);
        }
    }
    return malformed(QStringLiteral("the output is truncated"));
}

} // namespace

Result parseShareOutput(const QByteArray &output, QVector<ShareInfo> *shares)
{
    shares->clear();
    QList<QByteArray> lines;
    Result r = splitLines(output, &lines);
    QVector<ShareInfo> parsed;
    if (r.ok())
        r = parseLines(lines, &parsed);
    // Nothing of a list that did not end well is used.
    if (r.ok())
        *shares = parsed;
    return r;
}

bool shareVisible(const ShareInfo &share, bool showAdminShares)
{
    if ((share.type & ShareTypeMask) != ShareTypeDiskTree)
        return false;
    return showAdminShares || !share.name.endsWith(QLatin1Char('$'));
}

} // namespace NetVfs::Smb
