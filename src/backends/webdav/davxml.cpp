// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davxml.h"
#include "davstatus.h"
#include "names.h"

#include <QtCore/QStringList>

#include <algorithm>
#include <cctype>

namespace NetVfs::WebDav {

namespace {

constexpr const char *DavNs = "DAV:";
constexpr const char *OcNs = "http://owncloud.org/ns";

// Depths in the element stack (multistatus = 1).
constexpr int ResponseDepth = 2;
constexpr int ResponseChildDepth = 3;   // href, status, propstat
constexpr int PropstatChildDepth = 4;   // prop, status
constexpr int PropertyDepth = 5;
constexpr int PropertyChildDepth = 6;

bool is2xx(int status)
{
    return status >= 200 && status < 300;
}

bool isHex(const QString &text)
{
    return std::all_of(text.begin(), text.end(),
                       [](QChar c) { return std::isxdigit(static_cast<unsigned char>(c.toLatin1())) != 0; });
}

qint64 toCount(const QString &text)
{
    bool ok = false;
    const qint64 value = text.trimmed().toLongLong(&ok);
    return ok && value >= 0 ? value : -1;
}

QDateTime isoDate(const QString &text)
{
    const QDateTime parsed = QDateTime::fromString(text.trimmed(), Qt::ISODate);
    return parsed.isValid() ? parsed.toUTC() : QDateTime();
}

// Fields set in `from` override `to` (one response may split its
// properties over several 2xx propstats).
void merge(const DavResource &from, DavResource *to)
{
    if (from.typeKnown) {
        to->typeKnown = true;
        to->collection = from.collection;
    }
    if (from.contentLength >= 0)
        to->contentLength = from.contentLength;
    if (from.modified.isValid())
        to->modified = from.modified;
    if (from.created.isValid())
        to->created = from.created;
    if (!from.etag.isEmpty())
        to->etag = from.etag;
    if (!from.contentType.isEmpty())
        to->contentType = from.contentType;
    if (from.quotaAvailable >= 0)
        to->quotaAvailable = from.quotaAvailable;
    if (from.quotaUsed >= 0)
        to->quotaUsed = from.quotaUsed;
    to->hidden = to->hidden || from.hidden;
    if (from.hasPermissions) {
        to->hasPermissions = true;
        to->permissions = from.permissions;
    }
    if (!from.fileId.isEmpty())
        to->fileId = from.fileId;
    if (!from.checksums.isEmpty())
        to->checksums = from.checksums;
}

// Nextcloud permission letters: W write (file), C/K create file/folder.
bool readOnlyByPermissions(const DavResource &resource)
{
    if (resource.collection)
        return !resource.permissions.contains(QLatin1Char('C')) && !resource.permissions.contains(QLatin1Char('K'));
    return !resource.permissions.contains(QLatin1Char('W'));
}

} // namespace

QByteArray propfindBody(bool nextcloud)
{
    QByteArray body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                      "<d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:prop>"
                      "<d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:creationdate/>"
                      "<d:getetag/><d:getcontenttype/><d:quota-available-bytes/><d:quota-used-bytes/>"
                      "<d:ishidden/>";
    if (nextcloud)
        body += "<oc:permissions/><oc:fileid/><oc:checksums/>";
    body += "</d:prop></d:propfind>\n";
    return body;
}

MultistatusParser::MultistatusParser(Callback callback, qint64 maxBytes, int maxDepth)
    : m_callback(std::move(callback))
    , m_maxBytes(maxBytes)
    , m_maxDepth(maxDepth)
{
    m_reader.setNamespaceProcessing(true);
}

bool MultistatusParser::feed(const char *data, qint64 size)
{
    if (!m_result.ok() || m_stopped)
        return false;
    m_fed += size;
    if (m_fed > m_maxBytes) {
        fail(QStringLiteral("The folder listing is larger than %1 MiB").arg(m_maxBytes >> 20));
        return false;
    }
    m_reader.addData(QByteArray(data, int(size)));
    parse();
    return m_result.ok() && !m_stopped;
}

Result MultistatusParser::finish()
{
    if (!m_result.ok() || m_stopped)
        return m_result;
    parse();
    if (m_result.ok() && !m_rootClosed)
        fail(QStringLiteral("The multistatus response is incomplete"));
    return m_result;
}

void MultistatusParser::fail(const QString &message)
{
    if (m_result.ok())
        m_result = Result(Error::ProtocolError, QStringLiteral("Invalid WebDAV response: %1").arg(message));
}

bool MultistatusParser::isAt(int depth, const char *ns, const char *name) const
{
    if (depth < 1 || depth > m_stack.size())
        return false;
    const Element &element = m_stack.at(depth - 1);
    return element.name == QLatin1String(name) && element.ns == QLatin1String(ns);
}

void MultistatusParser::parse()
{
    while (m_result.ok() && !m_stopped && !m_reader.atEnd()) {
        switch (m_reader.readNext()) {
        case QXmlStreamReader::DTD:
            fail(QStringLiteral("document type declarations are not accepted"));
            break;
        case QXmlStreamReader::EntityReference:
            fail(QStringLiteral("entity references are not accepted"));
            break;
        case QXmlStreamReader::StartElement:
            startElement();
            break;
        case QXmlStreamReader::EndElement:
            endElement();
            break;
        case QXmlStreamReader::Characters:
            characters();
            break;
        default:
            break;
        }
    }
    if (m_reader.hasError() && m_reader.error() != QXmlStreamReader::PrematureEndOfDocumentError)
        fail(m_reader.errorString());
}

void MultistatusParser::startElement()
{
    if (m_rootClosed) {
        fail(QStringLiteral("content after the document"));
        return;
    }
    m_stack.append(Element { m_reader.namespaceUri().toString(), m_reader.name().toString() });
    const int depth = m_stack.size();
    if (depth > m_maxDepth) {
        fail(QStringLiteral("elements nested deeper than %1").arg(m_maxDepth));
        return;
    }
    if (depth == 1) {
        if (!isAt(1, DavNs, "multistatus"))
            fail(QStringLiteral("not a multistatus document"));
        m_sawRoot = true;
    } else if (depth == ResponseDepth && isAt(ResponseDepth, DavNs, "response")) {
        m_current = DavResource();
    } else if (depth == ResponseChildDepth && isAt(ResponseChildDepth, DavNs, "propstat")) {
        m_propstat = DavResource();
        m_propstatStatus = 0;
        m_propstatHasStatus = false;
    } else if (depth == PropertyChildDepth && isAt(PropertyDepth, DavNs, "resourcetype")
               && isAt(PropertyChildDepth, DavNs, "collection")) {
        m_propstat.collection = true;
    }
    // Text of nested elements (oc:checksums/oc:checksum) accumulates,
    // separated by a space; any other element starts afresh.
    if (depth > PropertyDepth)
        m_text += QLatin1Char(' ');
    else
        m_text.clear();
}

void MultistatusParser::characters()
{
    if (m_stack.size() >= ResponseChildDepth)
        m_text += m_reader.text();
}

void MultistatusParser::endElement()
{
    if (m_stack.isEmpty())
        return;
    const int depth = m_stack.size();
    if (const bool inResponse = isAt(ResponseDepth, DavNs, "response"); inResponse && depth == ResponseChildDepth) {
        if (isAt(depth, DavNs, "href"))
            m_current.href = m_text.trimmed().toUtf8();
        else if (isAt(depth, DavNs, "status"))
            m_current.status = parseStatusLine(m_text);
        else if (isAt(depth, DavNs, "propstat"))
            endPropstat();
    } else if (inResponse && depth == PropstatChildDepth && isAt(ResponseChildDepth, DavNs, "propstat")
               && isAt(depth, DavNs, "status")) {
        m_propstatStatus = parseStatusLine(m_text);
        m_propstatHasStatus = true;
    } else if (inResponse && depth == PropertyDepth && isAt(PropstatChildDepth, DavNs, "prop")) {
        applyProperty(m_stack.last());
    } else if (inResponse && depth == ResponseDepth) {
        finishResponse();
    }
    m_stack.removeLast();
    if (m_stack.isEmpty())
        m_rootClosed = true;
}

void MultistatusParser::applyProperty(const Element &element)
{
    const QString text = m_text.trimmed();
    if (element.ns == QLatin1String(DavNs)) {
        if (const QString &name = element.name; name == QLatin1String("resourcetype"))
            m_propstat.typeKnown = true;
        else if (name == QLatin1String("getcontentlength"))
            m_propstat.contentLength = toCount(text);
        else if (name == QLatin1String("getlastmodified"))
            m_propstat.modified = parseHttpDate(text.toLatin1());
        else if (name == QLatin1String("creationdate"))
            m_propstat.created = isoDate(text);
        else if (name == QLatin1String("getetag"))
            m_propstat.etag = text.toUtf8();
        else if (name == QLatin1String("getcontenttype"))
            m_propstat.contentType = text;
        else if (name == QLatin1String("quota-available-bytes"))
            m_propstat.quotaAvailable = toCount(text);
        else if (name == QLatin1String("quota-used-bytes"))
            m_propstat.quotaUsed = toCount(text);
        else if (name == QLatin1String("ishidden"))
            m_propstat.hidden = text == QLatin1String("1") || text.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0;
    } else if (element.ns == QLatin1String(OcNs)) {
        if (element.name == QLatin1String("permissions")) {
            m_propstat.hasPermissions = true;
            m_propstat.permissions = text;
        } else if (element.name == QLatin1String("fileid")) {
            m_propstat.fileId = text;
        } else if (element.name == QLatin1String("checksums")) {
            m_propstat.checksums = text.simplified();
        }
    }
}

void MultistatusParser::endPropstat()
{
    // A propstat without <status> is taken as 200; servers that omit it
    // only ever do so for found properties.
    if (!m_propstatHasStatus || is2xx(m_propstatStatus))
        merge(m_propstat, &m_current);
}

void MultistatusParser::finishResponse()
{
    ++m_responses;
    if (m_callback && !m_callback(m_current))
        m_stopped = true;
}

int parseStatusLine(const QString &line)
{
    const QStringList parts = line.simplified().split(QLatin1Char(' '));
    if (parts.size() < 2 || !parts.at(0).startsWith(QLatin1String("HTTP/")))
        return 0;
    bool ok = false;
    const int status = parts.at(1).toInt(&ok);
    return ok ? status : 0;
}

QMap<QString, QByteArray> parseChecksums(const QString &text)
{
    QMap<QString, QByteArray> result;
    for (const QString &item : text.simplified().split(QLatin1Char(' '), NETVFS_SKIP_EMPTY_PARTS)) {
        const int colon = item.indexOf(QLatin1Char(':'));
        if (colon <= 0)
            continue;
        const QString digest = item.mid(colon + 1);
        if (digest.isEmpty() || digest.size() % 2 != 0 || !isHex(digest))
            continue;
        result.insert(item.left(colon).toLower(), QByteArray::fromHex(digest.toLatin1()));
    }
    return result;
}

Entry toEntry(const DavResource &resource, const QString &name, bool nextcloud)
{
    Entry entry;
    entry.name = name;
    if (resource.typeKnown)
        entry.type = resource.collection ? EntryType::Directory : EntryType::File;
    if (!resource.collection)
        entry.size = resource.contentLength;
    entry.modified = resource.modified;
    entry.created = resource.created;
    entry.etag = resource.etag;
    entry.contentType = resource.contentType;
    if (resource.hidden)
        entry.flags |= EntryFlag::Hidden;
    if (Names::hasEscapes(name))
        entry.flags |= EntryFlag::NameNotUtf8;
    if (nextcloud) {
        if (!resource.fileId.isEmpty())
            entry.extra.insert(QStringLiteral("oc:fileid"), resource.fileId);
        if (resource.hasPermissions) {
            entry.extra.insert(QStringLiteral("oc:permissions"), resource.permissions);
            if (readOnlyByPermissions(resource))
                entry.flags |= EntryFlag::ReadOnly;
        }
    }
    return entry;
}

bool toSpaceInfo(const DavResource &resource, SpaceInfo *out)
{
    if (resource.quotaAvailable < 0 && resource.quotaUsed < 0)
        return false;
    SpaceInfo info;
    info.free = resource.quotaAvailable;
    info.used = resource.quotaUsed;
    if (info.free >= 0 && info.used >= 0)
        info.total = info.free + info.used;
    *out = info;
    return true;
}

} // namespace NetVfs::WebDav
