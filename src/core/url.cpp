// SPDX-License-Identifier: LGPL-2.1-or-later
#include "url.h"
#include "names.h"
#include "paths.h"

#include <QtCore/QUrl>

#include <array>

namespace NetVfs::Url {

namespace {

constexpr int MaxPort = 65535;
constexpr int MaxPortDigits = 5;
constexpr ushort FirstPrintable = 0x20;
constexpr ushort Delete = 0x7F;

enum class Kind { Sftp, Smb, WebDav, Ftp, Local };

struct SchemeInfo {
    const char *scheme;
    Kind kind;
    int defaultPort;
    const char *mode;    // webdav: "tls" option, ftp: "tls_mode" option; unused otherwise
};

constexpr std::array<SchemeInfo, 10> Schemes = {{
    { "sftp", Kind::Sftp, 22, nullptr },
    { "ssh", Kind::Sftp, 22, nullptr },
    { "smb", Kind::Smb, 445, nullptr },
    { "dav", Kind::WebDav, 80, "http" },
    { "davs", Kind::WebDav, 443, "https" },
    { "http", Kind::WebDav, 80, "http" },
    { "https", Kind::WebDav, 443, "https" },
    { "ftp", Kind::Ftp, 21, "explicit" },
    { "ftps", Kind::Ftp, 990, "implicit" },
    { "file", Kind::Local, 0, nullptr },
}};

const SchemeInfo *findScheme(const QString &scheme)
{
    for (const SchemeInfo &info : Schemes) {
        if (scheme == QLatin1String(info.scheme))
            return &info;
    }
    return nullptr;
}

Result invalid(const char *what)
{
    return Result(Error::InvalidName, QStringLiteral("Malformed URL: %1").arg(QLatin1String(what)));
}

bool hasControlCharacter(const QString &text)
{
    for (const QChar c : text) {
        if (c.unicode() < FirstPrintable || c.unicode() == Delete)
            return true;
    }
    return false;
}

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// Raw characters are taken as their lossless UTF-8 bytes (Names::encode), then
// "%XX" escapes are decoded to bytes; a bad escape fails.
bool percentDecode(const QString &text, QByteArray *bytes)
{
    const QByteArray raw = Names::encode(text);
    QByteArray out;
    out.reserve(raw.size());
    for (int i = 0; i < raw.size(); ++i) {
        if (raw.at(i) != '%') {
            out.append(raw.at(i));
            continue;
        }
        const int high = i + 2 < raw.size() ? hexValue(raw.at(i + 1)) : -1;
        const int low = i + 2 < raw.size() ? hexValue(raw.at(i + 2)) : -1;
        if (high < 0 || low < 0)
            return false;
        out.append(char(high * 16 + low));
        i += 2;
    }
    *bytes = out;
    return true;
}

bool isUnreserved(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
        || c == '-' || c == '.' || c == '_' || c == '~';
}

QString percentEncode(const QString &text, bool keepSlash)
{
    static const char hex[] = "0123456789ABCDEF";
    const QByteArray bytes = Names::encode(text);
    QString out;
    out.reserve(bytes.size());
    for (const char c : bytes) {
        if (isUnreserved(c) || (keepSlash && c == '/')) {
            out.append(QLatin1Char(c));
        } else {
            out.append(QLatin1Char('%'));
            out.append(QLatin1Char(hex[(uchar(c) >> 4) & 0x0F]));
            out.append(QLatin1Char(hex[uchar(c) & 0x0F]));
        }
    }
    return out;
}

// Decodes a user name or a path: percent escapes to bytes, then the lossless
// codec (XC-4).
bool decodeText(const QString &text, QString *out)
{
    QByteArray bytes;
    if (!percentDecode(text, &bytes))
        return false;
    *out = Names::decode(bytes);
    return true;
}

bool isAscii(const QString &text)
{
    for (const QChar c : text) {
        if (c.unicode() > 0x7F)
            return false;
    }
    return true;
}

bool validHostCharacters(const QString &host)
{
    static const QString forbidden = QStringLiteral("/\\?#@[]:% <>\"^`{|}");
    for (const QChar c : host) {
        if (c.unicode() < FirstPrintable || c.unicode() == Delete || forbidden.contains(c))
            return false;
    }
    return !host.isEmpty();
}

bool validIpv6(const QString &host)
{
    if (!host.contains(QLatin1Char(':')))
        return false;
    for (const QChar c : host) {
        const bool hex = (c >= QLatin1Char('0') && c <= QLatin1Char('9'))
            || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))
            || (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
        if (!hex && c != QLatin1Char(':') && c != QLatin1Char('.'))
            return false;
    }
    return true;
}

// Host name kept in Unicode: punycode labels are converted (QUrl::fromAce).
bool parseHostName(const QString &text, QString *host)
{
    QString decoded;
    if (!decodeText(text, &decoded) || Names::hasEscapes(decoded) || !validHostCharacters(decoded))
        return false;
    if (isAscii(decoded))
        decoded = QUrl::fromAce(decoded.toLatin1());
    *host = decoded;
    return !decoded.isEmpty();
}

bool parsePort(const QString &text, int *port)
{
    *port = 0;
    if (text.isEmpty())
        return true;
    if (text.size() > MaxPortDigits)
        return false;
    for (const QChar c : text) {
        if (c < QLatin1Char('0') || c > QLatin1Char('9'))
            return false;
    }
    *port = text.toInt();
    return *port >= 1 && *port <= MaxPort;
}

struct Authority {
    QString user;
    QString host;
    int port = 0;
};

Result parseHostPort(const QString &text, Authority *out)
{
    QString hostText;
    QString portText;
    if (text.startsWith(QLatin1Char('['))) {
        const int close = text.indexOf(QLatin1Char(']'));
        if (close < 0)
            return invalid("unterminated IPv6 address");
        hostText = text.mid(1, close - 1);
        const QString rest = text.mid(close + 1);
        if (!rest.isEmpty() && !rest.startsWith(QLatin1Char(':')))
            return invalid("text after the IPv6 address");
        portText = rest.mid(1);
        if (!validIpv6(hostText))
            return invalid("bad IPv6 address");
        out->host = hostText;
    } else {
        const int colon = text.lastIndexOf(QLatin1Char(':'));
        hostText = colon < 0 ? text : text.left(colon);
        portText = colon < 0 ? QString() : text.mid(colon + 1);
        if (!hostText.isEmpty() && !parseHostName(hostText, &out->host))
            return invalid("bad host name");
    }
    if (!parsePort(portText, &out->port))
        return invalid("bad port");
    return Result::success();
}

Result parseAuthority(const QString &text, Authority *out)
{
    const int at = text.lastIndexOf(QLatin1Char('@'));
    if (at >= 0) {
        const QString userInfo = text.left(at);
        if (userInfo.contains(QLatin1Char(':')))
            return Result(Error::SecurityPolicy, QStringLiteral("passwords in URLs are not accepted"));
        if (!decodeText(userInfo, &out->user))
            return invalid("bad escape in the user name");
    }
    return parseHostPort(text.mid(at + 1), out);
}

Result parseScheme(const QString &url, const SchemeInfo **info, QString *rest)
{
    const int separator = url.indexOf(QLatin1String("://"));
    if (separator <= 0)
        return invalid("no scheme");
    const QString scheme = url.left(separator).toLower();
    for (const QChar c : scheme) {
        const bool letter = c >= QLatin1Char('a') && c <= QLatin1Char('z');
        const bool other = (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('+')
            || c == QLatin1Char('-') || c == QLatin1Char('.');
        if (!letter && !other)
            return invalid("bad scheme");
    }
    *info = findScheme(scheme);
    if (!*info)
        return Result(Error::Unsupported, QStringLiteral("Unsupported URL scheme \"%1\"").arg(scheme));
    *rest = url.mid(separator + 3);
    return Result::success();
}

Result parsePath(const QString &raw, QString *path)
{
    QString decoded;
    if (!decodeText(raw, &decoded))
        return invalid("bad escape in the path");
    // The raw path starts with '/', so the result is "/" or "/..." (never empty).
    return Paths::normalize(decoded, path);
}

QString withLeadingSlash(const QString &path)
{
    if (path.isEmpty() || path.startsWith(QLatin1Char('/')))
        return path;
    return QLatin1Char('/') + path;
}

// smb://host/share/dir: the first component is the share option.
void splitShare(const QString &urlPath, QString *share, QString *path)
{
    const QStringList parts = Paths::components(urlPath);
    if (parts.isEmpty())
        return;
    *share = parts.first();
    if (parts.size() > 1)
        *path = QLatin1Char('/') + QStringList(parts.mid(1)).join(QLatin1Char('/'));
}

void applyKind(const SchemeInfo &info, const QString &urlPath, ConnectionParams *params, QString *path)
{
    switch (info.kind) {
    case Kind::Sftp:
        params->provider = QStringLiteral("sftp");
        *path = urlPath;
        break;
    case Kind::Smb: {
        params->provider = QStringLiteral("smb");
        QString share;
        splitShare(urlPath, &share, path);
        if (!share.isEmpty())
            params->options.insert(QStringLiteral("share"), share);
        break;
    }
    case Kind::WebDav:
        params->provider = QStringLiteral("webdav");
        params->options.insert(QStringLiteral("tls"), QLatin1String(info.mode));
        if (urlPath.size() > 1)
            params->options.insert(QStringLiteral("base_path"), urlPath);
        break;
    case Kind::Ftp:
        params->provider = QStringLiteral("ftp");
        params->options.insert(QStringLiteral("tls_mode"), QLatin1String(info.mode));
        *path = urlPath;
        break;
    case Kind::Local:
        params->provider = QStringLiteral("local");
        params->host.clear();
        *path = urlPath;
        break;
    }
}

Result checkAuthority(const SchemeInfo &info, const Authority &authority)
{
    if (info.kind != Kind::Local) {
        if (authority.host.isEmpty())
            return invalid("no host");
        return Result::success();
    }
    if (!authority.user.isEmpty() || authority.port != 0)
        return invalid("a file URL has no user or port");
    if (!authority.host.isEmpty() && authority.host.toLower() != QLatin1String("localhost"))
        return Result(Error::Unsupported, QStringLiteral("file URLs with a remote host are not supported"));
    return Result::success();
}

const char *schemeFor(const ConnectionParams &params)
{
    if (params.provider == QLatin1String("sftp"))
        return "sftp";
    if (params.provider == QLatin1String("smb"))
        return "smb";
    if (params.provider == QLatin1String("webdav"))
        return params.option(QStringLiteral("tls"), QStringLiteral("https")) == QLatin1String("http") ? "http" : "https";
    if (params.provider == QLatin1String("ftp"))
        return params.option(QStringLiteral("tls_mode")) == QLatin1String("implicit") ? "ftps" : "ftp";
    if (params.provider == QLatin1String("local"))
        return "file";
    return nullptr;
}

QString joinUrlPath(const QString &base, const QString &path)
{
    QString trimmedBase = base;
    while (trimmedBase.endsWith(QLatin1Char('/')))
        trimmedBase.chop(1);
    QString trimmedPath = path;
    while (trimmedPath.startsWith(QLatin1Char('/')))
        trimmedPath.remove(0, 1);
    if (trimmedPath.isEmpty())
        return trimmedBase;
    return trimmedBase + QLatin1Char('/') + trimmedPath;
}

QString encodedLocation(const ConnectionParams &params, const QString &path)
{
    if (params.provider == QLatin1String("webdav")) {
        const QString base = withLeadingSlash(params.option(QStringLiteral("base_path")));
        return percentEncode(withLeadingSlash(joinUrlPath(base, path)), true);
    }
    if (params.provider == QLatin1String("smb")) {
        const QString share = params.option(QStringLiteral("share"));
        if (share.isEmpty())
            return QString();
        return QLatin1Char('/') + percentEncode(share, false)
            + percentEncode(withLeadingSlash(joinUrlPath(QString(), path)), true);
    }
    return percentEncode(withLeadingSlash(path), true);
}

QString authorityText(const ConnectionParams &params)
{
    QString out;
    if (!params.username.isEmpty())
        out += percentEncode(params.username, false) + QLatin1Char('@');
    if (params.host.contains(QLatin1Char(':')))
        out += QLatin1Char('[') + params.host + QLatin1Char(']');
    else
        out += params.host;
    if (params.port > 0)
        out += QLatin1Char(':') + QString::number(params.port);
    return out;
}

} // namespace

Result parse(const QString &url, ConnectionParams *params, QString *path)
{
    if (hasControlCharacter(url))
        return invalid("control character");
    const SchemeInfo *info = nullptr;
    QString rest;
    Result r = parseScheme(url, &info, &rest);
    if (!r.ok())
        return r;
    if (rest.contains(QLatin1Char('?')) || rest.contains(QLatin1Char('#')))
        return invalid("queries and fragments are not supported");

    const int slash = rest.indexOf(QLatin1Char('/'));
    Authority authority;
    r = parseAuthority(slash < 0 ? rest : rest.left(slash), &authority);
    if (r.ok())
        r = checkAuthority(*info, authority);
    if (!r.ok())
        return r;
    QString urlPath;
    if (slash >= 0)
        r = parsePath(rest.mid(slash), &urlPath);
    if (!r.ok())
        return r;

    ConnectionParams result = *params;
    for (const char *key : { "share", "tls", "base_path", "tls_mode" })
        result.options.remove(QLatin1String(key));
    result.host = authority.host;
    result.username = authority.user;
    result.port = authority.port == info->defaultPort ? 0 : authority.port;
    QString location;
    applyKind(*info, urlPath, &result, &location);
    *params = result;
    if (path)
        *path = location;
    return Result::success();
}

QString format(const ConnectionParams &params, const QString &path)
{
    const char *scheme = schemeFor(params);
    if (!scheme)
        return QString();
    return QLatin1String(scheme) + QLatin1String("://") + authorityText(params)
        + encodedLocation(params, path);
}

QByteArray toAce(const QString &host)
{
    QString bare = host;
    if (bare.startsWith(QLatin1Char('[')) && bare.endsWith(QLatin1Char(']')))
        bare = bare.mid(1, bare.size() - 2);
    if (bare.contains(QLatin1Char(':')))
        return bare.toLatin1();
    return QUrl::toAce(bare);
}

} // namespace NetVfs::Url
