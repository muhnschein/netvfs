// SPDX-License-Identifier: LGPL-2.1-or-later
#include "discoverytransport.h"

#include "addressclass.h"
#include "dnsmessage.h"
#include "logging.h"

#include <algorithm>
#include <utility>

namespace NetVfs {

namespace {

constexpr int MulticastTtl = 255;                // RFC 6762 section 11

const QHostAddress &group4()
{
    static const QHostAddress g(QStringLiteral("224.0.0.251"));
    return g;
}

const QHostAddress &group6()
{
    static const QHostAddress g(QStringLiteral("ff02::fb"));
    return g;
}

bool hasAddressOfFamily(const QNetworkInterface &iface, QAbstractSocket::NetworkLayerProtocol family)
{
    const QList<QNetworkAddressEntry> entries = iface.addressEntries();
    return std::any_of(entries.begin(), entries.end(),
                       [family](const QNetworkAddressEntry &e) { return e.ip().protocol() == family; });
}

} // namespace

MulticastTransport::MulticastTransport(QObject *parent)
    : MulticastTransport(Options(), parent)
{
}

MulticastTransport::MulticastTransport(const Options &options, QObject *parent)
    : DiscoveryTransport(parent), m_options(options)
{
    connect(&m_v4, &QUdpSocket::readyRead, this, [this]() { readFrom(&m_v4); });
    connect(&m_v6, &QUdpSocket::readyRead, this, [this]() { readFrom(&m_v6); });
}

MulticastTransport::~MulticastTransport()
{
    close();
}

bool MulticastTransport::isOpen() const
{
    return m_open;
}

quint16 MulticastTransport::localPort() const
{
    return m_v4Bound ? m_v4.localPort() : 0;
}

bool MulticastTransport::bindSocket(QUdpSocket *socket, const QHostAddress &any) const
{
    if (!socket->bind(any, m_options.port, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint)) {
        qCDebug(lcNetVfsCore) << "mDNS: bind failed:" << socket->errorString();
        return false;
    }
    socket->setSocketOption(QAbstractSocket::MulticastTtlOption, MulticastTtl);
    socket->setSocketOption(QAbstractSocket::MulticastLoopbackOption, 1);
    return true;
}

bool MulticastTransport::open()
{
    if (m_open)
        return true;
    m_v4Bound = bindSocket(&m_v4, QHostAddress::AnyIPv4);
    m_v6Bound = m_options.ipv6 && bindSocket(&m_v6, QHostAddress::AnyIPv6);
    m_open = m_v4Bound || m_v6Bound;
    if (m_open)
        joinInterfaces();
    return m_open;
}

void MulticastTransport::close()
{
    m_v4.close();
    m_v6.close();
    m_open = false;
    m_v4Bound = false;
    m_v6Bound = false;
    m_joined4.clear();
    m_joined6.clear();
    m_joinedNames4.clear();
    m_joinedNames6.clear();
    m_linkEntries.clear();
}

bool MulticastTransport::usableInterface(const QNetworkInterface &iface) const
{
    const QNetworkInterface::InterfaceFlags f = iface.flags();
    return (f & QNetworkInterface::IsUp) && (f & QNetworkInterface::IsRunning)
        && (f & QNetworkInterface::CanMulticast) && !(f & QNetworkInterface::IsLoopBack);
}

void MulticastTransport::joinInterface(const QNetworkInterface &iface)
{
    if (m_v4Bound && !m_joinedNames4.contains(iface.name())
        && hasAddressOfFamily(iface, QAbstractSocket::IPv4Protocol) && m_v4.joinMulticastGroup(group4(), iface)) {
        m_joinedNames4.insert(iface.name());
        m_joined4.append(iface);
    }
    if (m_v6Bound && !m_joinedNames6.contains(iface.name())
        && hasAddressOfFamily(iface, QAbstractSocket::IPv6Protocol) && m_v6.joinMulticastGroup(group6(), iface)) {
        m_joinedNames6.insert(iface.name());
        m_joined6.append(iface);
    }
}

void MulticastTransport::joinInterfaces()
{
    const QList<QNetworkInterface> all = QNetworkInterface::allInterfaces();
    m_linkEntries.clear();
    for (const QNetworkInterface &iface : all) {
        if (iface.flags() & QNetworkInterface::IsUp)
            m_linkEntries += iface.addressEntries();
        if (m_options.multicast && usableInterface(iface))
            joinInterface(iface);
    }
}

void MulticastTransport::send(const QByteArray &datagram)
{
    if (!m_open)
        return;
    joinInterfaces();       // interfaces that came up since the last query
    if (!m_options.multicast) {
        m_v4.writeDatagram(datagram, m_options.unicastAddress, m_options.unicastPort);
        return;
    }
    for (const QNetworkInterface &iface : std::as_const(m_joined4)) {
        m_v4.setMulticastInterface(iface);
        m_v4.writeDatagram(datagram, group4(), MdnsPort);
    }
    for (const QNetworkInterface &iface : std::as_const(m_joined6)) {
        m_v6.setMulticastInterface(iface);
        m_v6.writeDatagram(datagram, group6(), MdnsPort);
    }
}

bool MulticastTransport::isOnLink(const QHostAddress &sender, const QList<QNetworkAddressEntry> &entries)
{
    if (AddressClass::isIpv6LinkLocal(sender))
        return true;
    return std::any_of(entries.begin(), entries.end(), [&sender](const QNetworkAddressEntry &e) {
        return e.ip().protocol() == sender.protocol() && e.prefixLength() >= 0
            && sender.isInSubnet(e.ip(), e.prefixLength());
    });
}

bool MulticastTransport::onLink(const QHostAddress &sender) const
{
    return !m_options.onLinkOnly || isOnLink(sender, m_linkEntries);
}

void MulticastTransport::readFrom(QUdpSocket *socket)
{
    while (socket->hasPendingDatagrams()) {
        const qint64 size = socket->pendingDatagramSize();
        if (size < 0)
            break;
        QByteArray buffer(static_cast<int>(size), Qt::Uninitialized);
        QHostAddress sender;
        quint16 senderPort = 0;
        const qint64 got = socket->readDatagram(buffer.data(), buffer.size(), &sender, &senderPort);
        if (got < 0 || got > Dns::MaxPacketSize)
            continue;
        buffer.truncate(static_cast<int>(got));
        if (m_options.requiredSourcePort != 0 && senderPort != m_options.requiredSourcePort)
            continue;
        if (!onLink(sender))
            continue;
        emit datagramReceived(buffer, sender);
    }
}

} // namespace NetVfs
