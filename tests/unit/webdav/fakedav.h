// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FAKEDAV_H
#define NETVFS_FAKEDAV_H

#include "httptestserver.h"

#include <QtCore/QMap>
#include <QtCore/QStringList>

#include <mutex>

// A small in-memory WebDAV server (RFC 4918 subset) for HttpTestServer:
// OPTIONS, PROPFIND (Depth 0/1), MKCOL, GET (Range), PUT (If-None-Match),
// PATCH (sabre/dav append), DELETE, MOVE, COPY (Overwrite, Depth). Resources
// live below `prefix`; paths are byte strings ("/a/b").
class FakeDav
{
public:
    struct Node {
        bool collection = false;
        QByteArray data;
    };

    QByteArray prefix = "/dav";
    QByteArray authorization;          // required "Authorization" value; empty: none
    QByteArray davHeader = "1, 2";
    bool ranges = true;                // honour Range
    qint64 quotaAvailable = -1;        // reported when >= 0
    qint64 quotaUsed = -1;
    QByteArray extraPropXml;           // inserted into every 200 propstat

    FakeDav();
    HttpReply handle(const HttpRequestRecord &request);
    // For "Expect: 100-continue": authorization and preconditions are
    // checked before the body, as Apache and sabre/dav do.
    HttpReply expect(const HttpRequestRecord &request);

    void addFile(const QByteArray &path, const QByteArray &data);
    void addFolder(const QByteArray &path);
    bool exists(const QByteArray &path) const;
    Node node(const QByteArray &path) const;

    static QByteArray encodePath(const QByteArray &path);

private:
    QByteArray pathOf(const QByteArray &target) const;
    QByteArray parentOf(const QByteArray &path) const;
    QByteArray hrefOf(const QByteArray &path, const Node &node) const;
    QByteArray responseXml(const QByteArray &path, const Node &node) const;
    HttpReply propfind(const HttpRequestRecord &request, const QByteArray &path);
    HttpReply get(const HttpRequestRecord &request, const QByteArray &path);
    HttpReply put(const HttpRequestRecord &request, const QByteArray &path);
    HttpReply transfer(const HttpRequestRecord &request, const QByteArray &path, bool move);
    HttpReply remove(const QByteArray &path);

    mutable std::recursive_mutex m_lock;
    QMap<QByteArray, Node> m_nodes;
};

#endif
