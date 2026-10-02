// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davstatus.h"

#include <QtCore/QStringList>

#include <array>

namespace NetVfs::WebDav {

namespace {

constexpr int StatusNotModified = 304;
constexpr int StatusMethodNotAllowed = 405;
constexpr int StatusTooManyRequests = 429;
constexpr int StatusUnavailable = 503;
constexpr qint64 MsPerSecond = 1000;
constexpr int TwoDigitYearPivot = 70;
constexpr int Century19 = 1900;
constexpr int Century20 = 2000;

struct StatusRule {
    int status;
    Error error;
    const char *message;
};

// W-13; 405 (MKCOL), 429 and 503 are handled in httpResult().
const std::array<StatusRule, 10> statusRules = { {
    { 400, Error::ProtocolError, "The server rejected the request as malformed" },
    { 401, Error::AuthFailed, "The server did not accept the user name or password" },
    { 403, Error::PermissionDenied, "Permission denied" },
    { 404, Error::NotFound, "No such file or folder" },
    { 409, Error::NotFound, "The parent folder does not exist" },
    { 412, Error::AlreadyExists, "The target already exists" },
    { 414, Error::InvalidName, "The path is too long for the server" },
    { 415, Error::Unsupported, "The server does not support this request" },
    { 423, Error::Locked, "The file is locked" },
    { 507, Error::NoSpace, "Not enough space on the server" },
} };

int monthFromName(const QByteArray &token)
{
    static const QList<QByteArray> months = { "jan", "feb", "mar", "apr", "may", "jun",
                                              "jul", "aug", "sep", "oct", "nov", "dec" };
    return months.indexOf(token.left(3).toLower()) + 1;
}

bool isNumber(const QByteArray &token)
{
    if (token.isEmpty())
        return false;
    for (const char c : token) {
        if (c < '0' || c > '9')
            return false;
    }
    return true;
}

struct DateParts {
    int day = 0;
    int month = 0;
    int year = -1;
    QTime time;
};

void takeToken(const QByteArray &token, DateParts *parts)
{
    if (token.contains(':')) {
        parts->time = QTime::fromString(QString::fromLatin1(token), QStringLiteral("hh:mm:ss"));
    } else if (isNumber(token)) {
        if (parts->day == 0 && token.size() <= 2) {
            parts->day = token.toInt();
        } else {
            int year = token.toInt();
            if (token.size() == 2)
                year += year >= TwoDigitYearPivot ? Century19 : Century20;
            parts->year = year;
        }
    } else if (parts->month == 0) {
        parts->month = monthFromName(token);
    }
}

} // namespace

QByteArray methodName(Method method)
{
    switch (method) {
    case Method::Options: return "OPTIONS";
    case Method::Propfind: return "PROPFIND";
    case Method::Proppatch: return "PROPPATCH";
    case Method::Mkcol: return "MKCOL";
    case Method::Get: return "GET";
    case Method::Put: return "PUT";
    case Method::Patch: return "PATCH";
    case Method::Delete: return "DELETE";
    case Method::Move: return "MOVE";
    case Method::Copy: return "COPY";
    }
    return QByteArray();
}

Result httpResult(int status, Method method, const QByteArray &reason, qint64 retryAfterMs)
{
    if (status >= 200 && status < 300)
        return Result::success();
    const QString detail = QStringLiteral("HTTP %1 %2 (%3)")
                               .arg(status)
                               .arg(QString::fromLatin1(reason.left(200)).trimmed(),
                                    QString::fromLatin1(methodName(method)));
    if (status == StatusNotModified)
        return Result(Error::NotModified, QStringLiteral("Not modified"), detail);
    if (status == StatusMethodNotAllowed) {
        if (method == Method::Mkcol)
            return Result(Error::AlreadyExists, QStringLiteral("The folder already exists"), detail);
        return Result(Error::Unsupported, QStringLiteral("The server does not allow this operation here"), detail);
    }
    if (status == StatusTooManyRequests || (status == StatusUnavailable && retryAfterMs >= 0)) {
        return Result(Error::RateLimited, QStringLiteral("The server asks to retry later"), detail,
                      retryAfterMs);
    }
    for (const StatusRule &rule : statusRules) {
        if (rule.status == status)
            return Result(rule.error, QLatin1String(rule.message), detail);
    }
    if (status >= 300 && status < 400)
        return Result(Error::ProtocolError, QStringLiteral("Unexpected redirect"), detail);
    return Result(Error::ProtocolError, QStringLiteral("The server answered with status %1").arg(status), detail);
}

QDateTime parseHttpDate(const QByteArray &value)
{
    QByteArray normalized = value.trimmed();
    normalized.replace(',', ' ');
    normalized.replace('-', ' ');
    DateParts parts;
    for (const QByteArray &token : normalized.split(' ')) {
        if (!token.isEmpty())
            takeToken(token, &parts);
    }
    const QDate date(parts.year, parts.month, parts.day);
    if (!date.isValid() || !parts.time.isValid())
        return QDateTime();
    return QDateTime(date, parts.time, Qt::UTC);
}

qint64 parseRetryAfter(const QByteArray &value, const QDateTime &now)
{
    const QByteArray trimmed = value.trimmed();
    if (trimmed.isEmpty())
        return -1;
    if (isNumber(trimmed)) {
        bool ok = false;
        const qint64 seconds = trimmed.toLongLong(&ok);
        return ok ? seconds * MsPerSecond : -1;
    }
    const QDateTime when = parseHttpDate(trimmed);
    if (!when.isValid())
        return -1;
    return qMax<qint64>(0, now.msecsTo(when));
}

qint64 contentRangeStart(const QByteArray &value)
{
    const QByteArray trimmed = value.trimmed();
    if (!trimmed.startsWith("bytes "))
        return -1;
    const QByteArray range = trimmed.mid(6).trimmed();
    const int dash = range.indexOf('-');
    if (dash <= 0)
        return -1;
    const QByteArray start = range.left(dash);
    if (!isNumber(start))
        return -1;
    bool ok = false;
    const qint64 position = start.toLongLong(&ok);
    return ok ? position : -1;
}

} // namespace NetVfs::WebDav
