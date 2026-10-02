// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakedav.h"

namespace {

constexpr int Ok = 200;
constexpr int Created = 201;
constexpr int NoContent = 204;
constexpr int Partial = 206;
constexpr int MultiStatus = 207;
constexpr int Unauthorized = 401;
constexpr int Forbidden = 403;
constexpr int NotFoundStatus = 404;
constexpr int NotAllowed = 405;
constexpr int Conflict = 409;
constexpr int PreconditionFailed = 412;
constexpr int RangeNotSatisfiable = 416;

bool isUnreserved(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
        || c == '_' || c == '~';
}

QByteArray xml(const QByteArray &inner)
{
    return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\">" + inner + "</d:multistatus>\n";
}

} // namespace

FakeDav::FakeDav()
{
    m_nodes.insert(QByteArray(), Node { true, QByteArray() });
}

QByteArray FakeDav::encodePath(const QByteArray &path)
{
    QByteArray out;
    for (const char c : path) {
        if (isUnreserved(c) || c == '/')
            out += c;
        else
            out += '%' + QByteArray(1, c).toHex().toUpper();
    }
    return out;
}

void FakeDav::addFile(const QByteArray &path, const QByteArray &data)
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    m_nodes.insert(path, Node { false, data });
}

void FakeDav::addFolder(const QByteArray &path)
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    m_nodes.insert(path, Node { true, QByteArray() });
}

bool FakeDav::exists(const QByteArray &path) const
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    return m_nodes.contains(path);
}

FakeDav::Node FakeDav::node(const QByteArray &path) const
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    return m_nodes.value(path);
}

QByteArray FakeDav::pathOf(const QByteArray &target) const
{
    QByteArray path = target;
    const int query = path.indexOf('?');
    if (query >= 0)
        path.truncate(query);
    if (!path.startsWith(prefix))
        return QByteArray("\x01");      // never a node
    QByteArray result;
    for (const QByteArray &segment : path.mid(prefix.size()).split('/')) {
        if (!segment.isEmpty())
            result += '/' + QByteArray::fromPercentEncoding(segment);
    }
    return result;
}

QByteArray FakeDav::parentOf(const QByteArray &path) const
{
    return path.left(qMax(0, path.lastIndexOf('/')));
}

QByteArray FakeDav::hrefOf(const QByteArray &path, const Node &node) const
{
    QByteArray href = prefix + encodePath(path);
    if (node.collection)
        href += '/';
    return href;
}

QByteArray FakeDav::responseXml(const QByteArray &path, const Node &node) const
{
    QByteArray props = node.collection ? "<d:resourcetype><d:collection/></d:resourcetype>" : "<d:resourcetype/>";
    if (!node.collection) {
        props += "<d:getcontentlength>" + QByteArray::number(node.data.size()) + "</d:getcontentlength>";
        props += "<d:getetag>\"e" + QByteArray::number(qHash(node.data)) + "\"</d:getetag>";
        props += "<d:getcontenttype>application/octet-stream</d:getcontenttype>";
    }
    props += "<d:getlastmodified>Mon, 01 Jan 2024 10:00:00 GMT</d:getlastmodified>";
    if (node.collection && quotaAvailable >= 0)
        props += "<d:quota-available-bytes>" + QByteArray::number(quotaAvailable) + "</d:quota-available-bytes>";
    if (node.collection && quotaUsed >= 0)
        props += "<d:quota-used-bytes>" + QByteArray::number(quotaUsed) + "</d:quota-used-bytes>";
    props += extraPropXml;
    return "<d:response><d:href>" + hrefOf(path, node) + "</d:href><d:propstat><d:prop>" + props
        + "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
          "<d:propstat><d:prop><d:creationdate/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
          "</d:response>";
}

HttpReply FakeDav::propfind(const HttpRequestRecord &request, const QByteArray &path)
{
    const QByteArray depth = request.header("depth");
    if (depth != "0" && depth != "1")
        return HttpReply::make(Forbidden, "infinity");
    if (!m_nodes.contains(path))
        return HttpReply::make(NotFoundStatus);
    const Node self = m_nodes.value(path);
    QByteArray inner = responseXml(path, self);
    if (depth == "1" && self.collection) {
        for (auto it = m_nodes.constBegin(); it != m_nodes.constEnd(); ++it) {
            if (!it.key().isEmpty() && parentOf(it.key()) == path)
                inner += responseXml(it.key(), it.value());
        }
    }
    return HttpReply::make(MultiStatus, xml(inner)).with("Content-Type", "application/xml; charset=utf-8");
}

HttpReply FakeDav::get(const HttpRequestRecord &request, const QByteArray &path)
{
    if (!m_nodes.contains(path))
        return HttpReply::make(NotFoundStatus);
    const QByteArray data = m_nodes.value(path).data;
    const QByteArray range = request.header("range");
    if (!ranges || !range.startsWith("bytes="))
        return HttpReply::make(Ok, data);
    const QList<QByteArray> bounds = range.mid(6).split('-');
    const qint64 first = bounds.value(0).toLongLong();
    qint64 last = bounds.value(1).isEmpty() ? data.size() - 1 : bounds.value(1).toLongLong();
    if (first >= data.size())
        return HttpReply::make(RangeNotSatisfiable).with("Content-Range", "bytes */" + QByteArray::number(data.size()));
    last = qMin<qint64>(last, data.size() - 1);
    return HttpReply::make(Partial, data.mid(int(first), int(last - first + 1)))
        .with("Content-Range", "bytes " + QByteArray::number(first) + '-' + QByteArray::number(last) + '/'
                                   + QByteArray::number(data.size()));
}

HttpReply FakeDav::put(const HttpRequestRecord &request, const QByteArray &path)
{
    if (!m_nodes.value(parentOf(path)).collection || !m_nodes.contains(parentOf(path)))
        return HttpReply::make(Conflict);
    const bool existed = m_nodes.contains(path);
    if (existed && m_nodes.value(path).collection)
        return HttpReply::make(NotAllowed);
    if (request.method == "PATCH") {
        if (!existed)
            return HttpReply::make(NotFoundStatus);
        m_nodes[path].data += request.body;
        return HttpReply::make(NoContent);
    }
    if (existed && request.header("if-none-match") == "*")
        return HttpReply::make(PreconditionFailed);
    m_nodes.insert(path, Node { false, request.body });
    return HttpReply::make(existed ? NoContent : Created);
}

HttpReply FakeDav::remove(const QByteArray &path)
{
    if (!m_nodes.contains(path))
        return HttpReply::make(NotFoundStatus);
    const QList<QByteArray> keys = m_nodes.keys();
    for (const QByteArray &key : keys) {
        if (key == path || key.startsWith(path + '/'))
            m_nodes.remove(key);
    }
    return HttpReply::make(NoContent);
}

HttpReply FakeDav::transfer(const HttpRequestRecord &request, const QByteArray &path, bool move)
{
    if (!m_nodes.contains(path))
        return HttpReply::make(NotFoundStatus);
    QByteArray destination = request.header("destination");
    const int scheme = destination.indexOf("://");
    if (scheme >= 0)
        destination = destination.mid(destination.indexOf('/', scheme + 3));
    const QByteArray target = pathOf(destination);
    if (!m_nodes.value(parentOf(target)).collection || !m_nodes.contains(parentOf(target)))
        return HttpReply::make(Conflict);
    const bool existed = m_nodes.contains(target);
    if (existed && request.header("overwrite") == "F")
        return HttpReply::make(PreconditionFailed);
    if (existed)
        remove(target);
    const bool shallow = !move && request.header("depth") == "0";
    const QList<QByteArray> keys = m_nodes.keys();
    for (const QByteArray &key : keys) {
        const bool inside = key == path || (!shallow && key.startsWith(path + '/'));
        if (inside)
            m_nodes.insert(target + key.mid(path.size()), m_nodes.value(key));
    }
    if (move)
        remove(path);
    return HttpReply::make(existed ? NoContent : Created);
}

HttpReply FakeDav::expect(const HttpRequestRecord &request)
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    HttpReply reply;
    reply.proceed = true;
    const QByteArray path = pathOf(request.target);
    if (!authorization.isEmpty() && request.header("authorization") != authorization)
        reply = HttpReply::make(Unauthorized).with("WWW-Authenticate", "Basic realm=\"fake\"");
    else if (!m_nodes.contains(parentOf(path)))
        reply = HttpReply::make(Conflict);
    else if (m_nodes.contains(path) && request.header("if-none-match") == "*")
        reply = HttpReply::make(PreconditionFailed);
    return reply;
}

HttpReply FakeDav::handle(const HttpRequestRecord &request)
{
    std::lock_guard<std::recursive_mutex> lock(m_lock);
    if (request.method == "OPTIONS")
        return HttpReply::make(Ok).with("DAV", davHeader).with("Allow", "OPTIONS, PROPFIND, GET, PUT");
    if (!authorization.isEmpty() && request.header("authorization") != authorization)
        return HttpReply::make(Unauthorized).with("WWW-Authenticate", "Basic realm=\"fake\"");
    const QByteArray path = pathOf(request.target);
    if (request.method == "PROPFIND")
        return propfind(request, path);
    if (request.method == "GET")
        return get(request, path);
    if (request.method == "PUT" || request.method == "PATCH")
        return put(request, path);
    if (request.method == "DELETE")
        return remove(path);
    if (request.method == "MOVE" || request.method == "COPY")
        return transfer(request, path, request.method == "MOVE");
    if (request.method == "MKCOL") {
        if (m_nodes.contains(path))
            return HttpReply::make(NotAllowed);
        if (!m_nodes.contains(parentOf(path)))
            return HttpReply::make(Conflict);
        m_nodes.insert(path, Node { true, QByteArray() });
        return HttpReply::make(Created);
    }
    return HttpReply::make(NotAllowed);
}
