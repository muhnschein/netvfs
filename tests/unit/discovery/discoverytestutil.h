// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERYTESTUTIL_H
#define NETVFS_DISCOVERYTESTUTIL_H

#include "discovery.h"
#include "dnsmessage.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

// Helpers shared by the DNS codec tests and the discovery tests.
namespace NetVfs::Test {

// Builds a packet byte by byte, the way a capture would look: no encoder
// involved, so the decoder is checked against independently written bytes.
class Pkt
{
public:
    Pkt &u8(int v)
    {
        m_b.append(static_cast<char>(v));
        return *this;
    }
    Pkt &u16(int v) { return u8((v >> 8) & 0xFF).u8(v & 0xFF); }
    Pkt &u32(quint32 v) { return u16(static_cast<int>(v >> 16)).u16(static_cast<int>(v & 0xFFFF)); }
    // One label: length byte and bytes.
    Pkt &label(const QByteArray &l) { return u8(l.size()).raw(l); }
    // A whole name, uncompressed, with the root label.
    Pkt &name(const QByteArray &dotted)
    {
        const QList<QByteArray> parts = dotted.split('.');
        for (const QByteArray &p : parts) {
            if (!p.isEmpty())
                label(p);
        }
        return u8(0);
    }
    Pkt &ptr(int offset) { return u8(0xC0 | (offset >> 8)).u8(offset & 0xFF); }
    Pkt &raw(const QByteArray &b)
    {
        m_b.append(b);
        return *this;
    }
    Pkt &header(int id, int flags, int qd, int an, int ns, int ar)
    {
        return u16(id).u16(flags).u16(qd).u16(an).u16(ns).u16(ar);
    }
    int size() const { return m_b.size(); }
    // Patches a 16 bit value written earlier (record lengths).
    Pkt &patch16(int at, int v)
    {
        m_b[at] = static_cast<char>((v >> 8) & 0xFF);
        m_b[at + 1] = static_cast<char>(v & 0xFF);
        return *this;
    }
    QByteArray bytes() const { return m_b; }

private:
    QByteArray m_b;
};

inline QByteArray hexBytes(const char *hex)
{
    return QByteArray::fromHex(QByteArray(hex));
}

// Record builders for crafted responses.
inline Dns::Record ptrRecord(const QByteArray &type, const QByteArray &instance, quint32 ttl = 4500)
{
    Dns::Record r;
    r.name = type + ".local";
    r.type = Dns::TypePtr;
    r.ttl = ttl;
    r.target = instance + "." + type + ".local";
    return r;
}

inline Dns::Record srvRecord(const QByteArray &type, const QByteArray &instance, const QByteArray &target,
                             quint16 port, quint32 ttl = 120)
{
    Dns::Record r;
    r.name = instance + "." + type + ".local";
    r.type = Dns::TypeSrv;
    r.cacheFlush = true;
    r.ttl = ttl;
    r.port = port;
    r.target = target;
    return r;
}

inline Dns::Record txtRecord(const QByteArray &type, const QByteArray &instance, const QList<QByteArray> &strings,
                             quint32 ttl = 4500)
{
    Dns::Record r;
    r.name = instance + "." + type + ".local";
    r.type = Dns::TypeTxt;
    r.cacheFlush = true;
    r.ttl = ttl;
    r.txt = strings;
    return r;
}

inline Dns::Record addressRecord(const QByteArray &host, const QString &ip, quint32 ttl = 120, bool flush = true)
{
    Dns::Record r;
    r.name = host;
    r.address = QHostAddress(ip);
    r.type = r.address.protocol() == QAbstractSocket::IPv4Protocol ? Dns::TypeA : Dns::TypeAaaa;
    r.cacheFlush = flush;
    r.ttl = ttl;
    return r;
}

inline Dns::Message response(const QVector<Dns::Record> &answers, const QVector<Dns::Record> &additional = {})
{
    Dns::Message m;
    m.flags = Dns::FlagResponse | Dns::FlagAuthoritative;
    m.answers = answers;
    m.additional = additional;
    return m;
}

// A complete announcement in one datagram, as avahi sends it.
inline Dns::Message announcement(const QByteArray &type, const QByteArray &instance, const QByteArray &host,
                                 quint16 port, const QString &ip, const QList<QByteArray> &txt = {})
{
    return response({ptrRecord(type, instance)},
                    {srvRecord(type, instance, host, port), txtRecord(type, instance, txt),
                     addressRecord(host, ip)});
}

} // namespace NetVfs::Test

#endif
