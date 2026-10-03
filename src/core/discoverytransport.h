// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERYTRANSPORT_H
#define NETVFS_DISCOVERYTRANSPORT_H

#include "discovery.h"

#include <QtCore/QSet>
#include <QtNetwork/QNetworkAddressEntry>
#include <QtNetwork/QNetworkInterface>
#include <QtNetwork/QUdpSocket>

namespace NetVfs {

// SPEC-v2 XD-1: UDP multicast on 224.0.0.251 and ff02::fb, port 5353. The
// sockets are bound with ShareAddress | ReuseAddressHint so that they coexist
// with a system mDNS responder (avahi, systemd-resolved). Groups are joined on
// every interface that is up, can multicast and is not a loopback; interfaces
// that appear later are picked up at the next send(). IPv6 is optional: if its
// socket cannot be bound the transport runs on IPv4 alone.
//
// Datagrams are accepted only from the mDNS source port and from on-link
// senders (RFC 6762 section 11); anything else is dropped before parsing.
class NETVFS_EXPORT MulticastTransport final : public DiscoveryTransport
{
    Q_OBJECT

public:
    static constexpr quint16 MdnsPort = 5353;

    struct Options {
        quint16 port = MdnsPort;                 // local port to bind
        quint16 requiredSourcePort = MdnsPort;   // 0: accept any source port
        bool ipv6 = true;
        bool onLinkOnly = true;
        // Point-to-point mode for tests: no group is joined and send() goes
        // to this address and port instead of the multicast groups.
        bool multicast = true;
        QHostAddress unicastAddress;
        quint16 unicastPort = 0;
    };

    explicit MulticastTransport(QObject *parent = nullptr);
    explicit MulticastTransport(const Options &options, QObject *parent = nullptr);
    ~MulticastTransport() override;

    bool open() override;
    void close() override;
    bool isOpen() const override;
    void send(const QByteArray &datagram) override;

    // Bound IPv4 port (0 when closed); the ephemeral port when Options::port is 0.
    quint16 localPort() const;

    // True if `sender` is link-local or inside a subnet of one of `entries`.
    static bool isOnLink(const QHostAddress &sender, const QList<QNetworkAddressEntry> &entries);

private:
    void readFrom(QUdpSocket *socket);
    bool bindSocket(QUdpSocket *socket, const QHostAddress &any) const;
    void joinInterfaces();
    void joinInterface(const QNetworkInterface &iface);
    bool usableInterface(const QNetworkInterface &iface) const;
    bool onLink(const QHostAddress &sender) const;

    Options m_options;
    QUdpSocket m_v4;
    QUdpSocket m_v6;
    bool m_open = false;
    bool m_v4Bound = false;
    bool m_v6Bound = false;
    QList<QNetworkInterface> m_joined4;
    QList<QNetworkInterface> m_joined6;
    QSet<QString> m_joinedNames4;
    QSet<QString> m_joinedNames6;
    QList<QNetworkAddressEntry> m_linkEntries;   // addresses of up interfaces, for onLink()
};

} // namespace NetVfs

#endif
