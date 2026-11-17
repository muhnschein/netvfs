// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ADDRESSCLASS_H
#define NETVFS_ADDRESSCLASS_H

#include <QtNetwork/QHostAddress>

#include <cstddef>

namespace NetVfs::AddressClass {

constexpr quint8 LinkLocalFirstByte = 0xFE;
constexpr std::byte LinkLocalSecondMask { 0xC0 };
constexpr std::byte LinkLocalSecondBits { 0x80 };

inline bool isIpv6LinkLocal(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv6Protocol)
        return false;
    const Q_IPV6ADDR bytes = address.toIPv6Address();
    const auto second = static_cast<std::byte>(bytes[1]);
    return bytes[0] == LinkLocalFirstByte && (second & LinkLocalSecondMask) == LinkLocalSecondBits;
}

}
#endif
