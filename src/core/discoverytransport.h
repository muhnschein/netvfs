// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERYTRANSPORT_H
#define NETVFS_DISCOVERYTRANSPORT_H

#include "discovery.h"

#include <QtCore/QSet>
#include <QtNetwork/QNetworkAddressEntry>
#include <QtNetwork/QNetworkInterface>
#include <QtNetwork/QUdpSocket>

namespace NetVfs {

// UDP multicast 224.0.0.251 / ff02::fb port 5353, bound ShareAddress
// ReuseAddressHint to coexist with avahi/systemd-resolved. Joins every up, multicast-capable,
// non-loopback interface; new ones picked up at next send(). IPv6 optional.
// Datagrams accepted only from the mDNS source port and on-link senders (RFC 6762 section 11).
class NETVFS_EXPORT MulticastTransport final : public DiscoveryTransport
{
    Q_OBJECT

public:
    static constexpr quint16 MdnsPort = 5353;

    struct Options {
        quint16 port = MdnsPort;
        quint16 requiredSourcePort = MdnsPort;
        bool ipv6 = true;
        bool onLinkOnly = true;
        // Test mode: no group joined; send() goes to this address and port.
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

    quint16 localPort() const;

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
    QList<QNetworkAddressEntry> m_linkEntries;
};

}
#endif
