// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVXML_H
#define NETVFS_DAVXML_H

#include "error.h"
#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QMap>
#include <QtCore/QXmlStreamReader>

#include <functional>

// WebDAV XML (RFC 4918) of the WebDAV backend: the PROPFIND request body and
// an incremental multistatus parser (SPEC-v2 W-7, XSEC-3).
namespace NetVfs::WebDav {

// Properties of one <response> element, from its 2xx propstats only (a
// property in a 404 propstat stays unknown, W-7).
struct DavResource {
    QByteArray href;                 // as sent (percent-encoded, maybe absolute)
    int status = 0;                  // response-level <status>, 0 if absent
    bool typeKnown = false;          // <resourcetype> was present
    bool collection = false;
    qint64 contentLength = -1;
    QDateTime modified;              // getlastmodified, UTC
    QDateTime created;               // creationdate, UTC
    QByteArray etag;
    QString contentType;
    qint64 quotaAvailable = -1;      // RFC 4331; negative server values stay -1
    qint64 quotaUsed = -1;
    bool hidden = false;             // DAV:ishidden (IIS)
    bool hasPermissions = false;
    QString permissions;             // oc:permissions
    QString fileId;                  // oc:fileid
    QString checksums;               // oc:checksums, "SHA1:… MD5:…"
};

// The PROPFIND body with the W-7 property set; `nextcloud` adds oc:*.
QByteArray propfindBody(bool nextcloud);

// Streams a multistatus body. Bytes are fed as they arrive (from the curl
// write callback); every completed <response> is passed to the callback,
// which returns false to stop parsing. XSEC-3: any DOCTYPE is rejected,
// elements nest at most `maxDepth` deep and at most `maxBytes` are accepted;
// each of these is a ProtocolError.
class MultistatusParser
{
public:
    static constexpr int DefaultMaxDepth = 64;
    static constexpr qint64 DefaultMaxBytes = qint64(64) << 20;

    using Callback = std::function<bool(const DavResource &)>;
    explicit MultistatusParser(Callback callback, qint64 maxBytes = DefaultMaxBytes,
                               int maxDepth = DefaultMaxDepth);

    // False once the body is invalid or the callback stopped; see result().
    bool feed(const char *data, qint64 size);
    // End of body: checks that the document is complete.
    Result finish();
    Result result() const { return m_result; }
    bool stopped() const { return m_stopped; }
    int responses() const { return m_responses; }

private:
    struct Element {
        QString ns;
        QString name;
    };
    bool isAt(int depth, const char *ns, const char *name) const;
    void parse();
    void startElement();
    void endElement();
    void characters();
    void fail(const QString &message);
    void applyProperty(const Element &element);
    void endPropstat();
    void finishResponse();

    Callback m_callback;
    qint64 m_maxBytes;
    int m_maxDepth;
    qint64 m_fed = 0;
    QXmlStreamReader m_reader;
    Result m_result;
    bool m_stopped = false;
    bool m_sawRoot = false;
    bool m_rootClosed = false;
    int m_responses = 0;

    QVector<Element> m_stack;
    QString m_text;
    DavResource m_current;
    DavResource m_propstat;          // properties of the current propstat
    int m_propstatStatus = 0;
    bool m_propstatHasStatus = false;
};

// "HTTP/1.1 404 Not Found" -> 404; 0 if unparsable.
int parseStatusLine(const QString &line);

// oc:checksums "SHA1:ab.. MD5:cd.." -> {"sha1": raw bytes, "md5": raw bytes}.
QMap<QString, QByteArray> parseChecksums(const QString &text);

// Entry from a resource (W-7). `name` is the decoded member name.
// `nextcloud`: oc:fileid and oc:permissions go to Entry::extra ("oc:fileid",
// "oc:permissions") and the permissions decide EntryFlag::ReadOnly.
Entry toEntry(const DavResource &resource, const QString &name, bool nextcloud);

// W-12: RFC 4331 quota properties as SpaceInfo; false when neither is known.
bool toSpaceInfo(const DavResource &resource, SpaceInfo *out);

} // namespace NetVfs::WebDav

#endif
