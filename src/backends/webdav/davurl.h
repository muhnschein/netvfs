// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVURL_H
#define NETVFS_DAVURL_H

#include "error.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

// URL handling of the WebDAV backend (SPEC-v2 W-2, W-6, W-7). Everything here
// works on wire bytes: path segments are Names::encode()d and percent-encoded,
// hrefs are percent-decoded back to bytes (XC-4).
namespace NetVfs::WebDav {

// scheme, host and effective port of a URL (RFC 6454).
struct Origin {
    QByteArray scheme;      // "http" | "https", lower case
    QByteArray host;        // ACE, lower case; IPv6 literals in brackets
    int port = 0;           // effective port (80/443 when the URL has none)

    bool isValid() const { return !scheme.isEmpty() && !host.isEmpty() && port > 0; }
    // "<scheme>://<host>[:<port>]", the port only when it is not the default.
    QByteArray toUrl() const;
    friend bool operator==(const Origin &a, const Origin &b)
    {
        return a.scheme == b.scheme && a.host == b.host && a.port == b.port;
    }
    friend bool operator!=(const Origin &a, const Origin &b) { return !(a == b); }
};

int defaultPort(const QByteArray &scheme);

// Host as it goes into a URL: punycode for IDN, brackets around IPv6
// literals, lower case. Empty if the host is not usable.
QByteArray hostForUrl(const QString &host);

// Percent-encodes everything except RFC 3986 unreserved characters.
QByteArray encodeSegment(const QByteArray &bytes);

// The encoded path of a netvfs path below the base: "a/b%20c" (no leading
// or trailing slash; empty for the base itself). InvalidName when a component
// cannot be encoded losslessly (XC-4).
Result encodeRelativePath(const QString &path, QByteArray *out);

// "/" + encoded components + "/" for the configured base path (W-2).
Result encodeBasePath(const QString &basePath, QByteArray *out);

// Splits an absolute http(s) URL. `path` is the encoded path without query
// and fragment ("/" when empty). False for anything else.
bool splitUrl(const QByteArray &url, Origin *origin, QByteArray *path);

// RFC 3986 5.2 reference resolution against an absolute http(s) URL,
// including dot-segment removal. Query and fragment of the reference are
// dropped. Empty when `base` is not an absolute http(s) URL.
QByteArray resolveReference(const QByteArray &base, const QByteArray &reference);

// W-6: the absolute target of a redirect from `current`, which must stay in
// `origin`; ProtocolError naming the target otherwise.
Result redirectTarget(const Origin &origin, const QByteArray &current, const QByteArray &location,
                      QByteArray *target);

// Percent-decodes each '/' separated segment of an encoded path; empty
// segments (repeated or trailing slashes) are dropped. A segment that
// decodes to bytes containing '/' or NUL is kept as is so that callers can
// reject it.
QVector<QByteArray> decodePathSegments(const QByteArray &encodedPath);

// W-7: where an href of a multistatus response points to, relative to the
// requested collection.
class HrefResolver
{
public:
    // `requestUrl`: the absolute URL the PROPFIND was sent to (after redirects).
    explicit HrefResolver(const QByteArray &requestUrl);

    enum class Kind { Self, Child, Other };
    // Child: `name` receives the decoded member name bytes. Other: a foreign
    // origin, a deeper descendant, a name with '/' or NUL, "." or "..".
    Kind classify(const QByteArray &href, QByteArray *name) const;

private:
    QByteArray m_requestUrl;
    Origin m_origin;
    QVector<QByteArray> m_segments;
    bool m_valid = false;
};

} // namespace NetVfs::WebDav

#endif
