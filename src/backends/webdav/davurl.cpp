// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davurl.h"
#include "names.h"
#include "paths.h"

#include <QtCore/QUrl>

namespace NetVfs::WebDav {

namespace {

constexpr int HttpPort = 80;
constexpr int HttpsPort = 443;
constexpr int MaxPort = 65535;
constexpr const char *HexDigits = "0123456789ABCDEF";

bool isUnreserved(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c == '-' || c == '.' || c == '_' || c == '~';
}

bool isHostNameChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

bool isIpv6Char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ':' || c == '.';
}

bool allOf(const QByteArray &bytes, bool (*predicate)(char))
{
    for (const char c : bytes) {
        if (!predicate(c))
            return false;
    }
    return true;
}

// Length of a URI scheme followed by ':' at the start of `reference`, or 0.
int schemeLength(const QByteArray &reference)
{
    for (int i = 0; i < reference.size(); ++i) {
        const char c = reference.at(i);
        const bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        if (c == ':')
            return i;
        if (i == 0 && !alpha)
            return 0;
        if (!alpha && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.')
            return 0;
    }
    return 0;
}

QByteArray stripQueryAndFragment(const QByteArray &reference)
{
    int end = reference.size();
    const int query = reference.indexOf('?');
    const int fragment = reference.indexOf('#');
    if (query >= 0)
        end = query;
    if (fragment >= 0 && fragment < end)
        end = fragment;
    return reference.left(end);
}

// RFC 3986 5.2.4.
QByteArray removeDotSegments(const QByteArray &path)
{
    QVector<QByteArray> output;
    const QList<QByteArray> parts = path.split('/');
    for (int i = 0; i < parts.size(); ++i) {
        const QByteArray &part = parts.at(i);
        const bool last = i == parts.size() - 1;
        if (part == ".") {
            if (last)
                output << QByteArray();
        } else if (part == "..") {
            if (output.size() > 1)
                output.removeLast();
            if (last)
                output << QByteArray();
        } else {
            output << part;
        }
    }
    QByteArray result;
    for (int i = 0; i < output.size(); ++i) {
        if (i > 0)
            result += '/';
        result += output.at(i);
    }
    if (!result.startsWith('/'))
        result.prepend('/');
    return result;
}

bool parseAuthority(const QByteArray &authority, const QByteArray &scheme, Origin *origin)
{
    if (authority.contains('@'))
        return false;   // user info is never accepted in a URL from the server
    QByteArray host;
    QByteArray port;
    if (authority.startsWith('[')) {
        const int close = authority.indexOf(']');
        if (close < 0)
            return false;
        host = authority.left(close + 1).toLower();
        if (!allOf(host.mid(1, host.size() - 2), isIpv6Char))
            return false;
        const QByteArray rest = authority.mid(close + 1);
        if (!rest.isEmpty() && !rest.startsWith(':'))
            return false;
        port = rest.mid(1);
    } else {
        const int colon = authority.lastIndexOf(':');
        host = (colon < 0 ? authority : authority.left(colon)).toLower();
        port = colon < 0 ? QByteArray() : authority.mid(colon + 1);
        if (host.isEmpty() || !allOf(host, isHostNameChar))
            return false;
    }
    int number = defaultPort(scheme);
    if (!port.isEmpty()) {
        bool ok = false;
        number = port.toInt(&ok);
        if (!ok || number <= 0 || number > MaxPort)
            return false;
    }
    origin->scheme = scheme;
    origin->host = host;
    origin->port = number;
    return true;
}

} // namespace

int defaultPort(const QByteArray &scheme)
{
    if (scheme == "https")
        return HttpsPort;
    if (scheme == "http")
        return HttpPort;
    return 0;
}

QByteArray Origin::toUrl() const
{
    QByteArray url = scheme + "://" + host;
    if (port != defaultPort(scheme))
        url += ':' + QByteArray::number(port);
    return url;
}

QByteArray hostForUrl(const QString &host)
{
    QString trimmed = host.trimmed();
    if (trimmed.startsWith(QLatin1Char('[')) && trimmed.endsWith(QLatin1Char(']')))
        trimmed = trimmed.mid(1, trimmed.size() - 2);
    if (trimmed.contains(QLatin1Char(':'))) {
        const QByteArray literal = trimmed.toLatin1().toLower();
        if (!allOf(literal, isIpv6Char))
            return QByteArray();
        return '[' + literal + ']';
    }
    const QByteArray ace = QUrl::toAce(trimmed).toLower();
    if (ace.isEmpty() || !allOf(ace, isHostNameChar))
        return QByteArray();
    return ace;
}

QByteArray encodeSegment(const QByteArray &bytes)
{
    QByteArray out;
    out.reserve(bytes.size() * 3);
    for (const char c : bytes) {
        if (isUnreserved(c)) {
            out += c;
        } else {
            const auto b = static_cast<uchar>(c);
            out += '%';
            out += HexDigits[b >> 4];
            out += HexDigits[b & 0x0F];
        }
    }
    return out;
}

Result encodeRelativePath(const QString &path, QByteArray *out)
{
    QString normalized;
    const Result r = Paths::normalize(path, &normalized);
    if (!r.ok())
        return Result(Error::InvalidName, r.message());
    QByteArray encoded;
    for (const QString &component : Paths::components(normalized)) {
        if (!Names::isEncodable(component))
            return Result(Error::InvalidName, QStringLiteral("The name cannot be stored on a WebDAV server"));
        if (!encoded.isEmpty())
            encoded += '/';
        encoded += encodeSegment(Names::encode(component));
    }
    *out = encoded;
    return Result::success();
}

Result encodeBasePath(const QString &basePath, QByteArray *out)
{
    QByteArray relative;
    const Result r = encodeRelativePath(basePath, &relative);
    if (!r.ok())
        return Result(Error::SecurityPolicy, QStringLiteral("Invalid base path: %1").arg(r.message()));
    *out = relative.isEmpty() ? QByteArray("/") : '/' + relative + '/';
    return Result::success();
}

bool splitUrl(const QByteArray &url, Origin *origin, QByteArray *path)
{
    const int separator = url.indexOf("://");
    if (separator <= 0)
        return false;
    const QByteArray scheme = url.left(separator).toLower();
    if (defaultPort(scheme) == 0)
        return false;
    const QByteArray rest = stripQueryAndFragment(url.mid(separator + 3));
    const int slash = rest.indexOf('/');
    const QByteArray authority = slash < 0 ? rest : rest.left(slash);
    Origin parsed;
    if (!parseAuthority(authority, scheme, &parsed))
        return false;
    if (origin)
        *origin = parsed;
    if (path)
        *path = slash < 0 ? QByteArray("/") : rest.mid(slash);
    return true;
}

QByteArray resolveReference(const QByteArray &base, const QByteArray &reference)
{
    Origin origin;
    QByteArray basePath;
    if (!splitUrl(base, &origin, &basePath))
        return QByteArray();
    const QByteArray ref = stripQueryAndFragment(reference.trimmed());
    QByteArray candidate;
    if (schemeLength(ref) > 0) {
        candidate = ref;
    } else if (ref.startsWith("//")) {
        candidate = origin.scheme + ':' + ref;
    } else {
        QByteArray path;
        if (ref.isEmpty())
            path = basePath;
        else if (ref.startsWith('/'))
            path = ref;
        else
            path = basePath.left(basePath.lastIndexOf('/') + 1) + ref;
        return origin.toUrl() + removeDotSegments(path);
    }
    QByteArray path;
    if (!splitUrl(candidate, &origin, &path))
        return QByteArray();
    return origin.toUrl() + removeDotSegments(path);
}

Result redirectTarget(const Origin &origin, const QByteArray &current, const QByteArray &location,
                      QByteArray *target)
{
    const QByteArray resolved = resolveReference(current, location);
    Origin to;
    if (resolved.isEmpty() || !splitUrl(resolved, &to, nullptr)) {
        return Result(Error::ProtocolError,
                      QStringLiteral("The server sent an unusable redirect to %1")
                          .arg(QString::fromLatin1(location.left(512))));
    }
    if (to != origin) {
        return Result(Error::ProtocolError,
                      QStringLiteral("The server redirected to %1, outside %2; check the server address")
                          .arg(QString::fromLatin1(resolved), QString::fromLatin1(origin.toUrl())));
    }
    *target = resolved;
    return Result::success();
}

QVector<QByteArray> decodePathSegments(const QByteArray &encodedPath)
{
    QVector<QByteArray> segments;
    for (const QByteArray &part : encodedPath.split('/')) {
        if (!part.isEmpty())
            segments << QByteArray::fromPercentEncoding(part);
    }
    return segments;
}

HrefResolver::HrefResolver(const QByteArray &requestUrl)
    : m_requestUrl(requestUrl)
{
    QByteArray path;
    m_valid = splitUrl(requestUrl, &m_origin, &path);
    m_segments = decodePathSegments(path);
}

HrefResolver::Kind HrefResolver::classify(const QByteArray &href, QByteArray *name) const
{
    if (!m_valid)
        return Kind::Other;
    const QByteArray resolved = resolveReference(m_requestUrl, href);
    Origin origin;
    QByteArray path;
    if (resolved.isEmpty() || !splitUrl(resolved, &origin, &path) || origin != m_origin)
        return Kind::Other;
    const QVector<QByteArray> segments = decodePathSegments(path);
    if (segments == m_segments)
        return Kind::Self;
    if (segments.size() != m_segments.size() + 1 || segments.mid(0, m_segments.size()) != m_segments)
        return Kind::Other;
    const QByteArray &last = segments.last();
    if (last.contains('/') || last.contains('\0') || last == "." || last == "..")
        return Kind::Other;
    if (name)
        *name = last;
    return Kind::Child;
}

} // namespace NetVfs::WebDav
