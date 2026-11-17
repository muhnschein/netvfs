// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DNSMESSAGE_H
#define NETVFS_DNSMESSAGE_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtNetwork/QHostAddress>

// DNS wire format for mDNS-SD (RFC 6762, 6763): questions and A, AAAA, PTR, SRV, TXT. Pure
// encoder/decoder, fuzzed (tests/fuzz/fuzz_dns_message.cpp).
// decode() takes UNTRUSTED input: bounds-checked, no forward pointers, names <= 255 wire bytes,
// labels <= 63, record counts must fit the packet. Malformed = whole message rejected.
// Names in presentation form: labels joined by '.', '.' and '\' in a label as "\." and "\\",
// control bytes "\DDD". No trailing dot; root is empty. Bytes >= 0x80 and spaces kept.
namespace NetVfs::Dns {

constexpr int HeaderSize = 12;
constexpr int MaxPacketSize = 9000;  // RFC 6762 section 17
constexpr int MaxLabelLength = 63;
constexpr int MaxNameLength = 255;
constexpr int MaxRecords = 512;

constexpr quint16 TypeA = 1;
constexpr quint16 TypePtr = 12;
constexpr quint16 TypeTxt = 16;
constexpr quint16 TypeAaaa = 28;
constexpr quint16 TypeSrv = 33;
constexpr quint16 TypeAny = 255;

constexpr quint16 ClassIn = 1;

constexpr quint16 FlagResponse = 0x8000;
constexpr quint16 FlagAuthoritative = 0x0400;
constexpr quint16 FlagTruncated = 0x0200;

struct NETVFS_EXPORT Question {
    QByteArray name;
    quint16 type = 0;
    quint16 cls = ClassIn;
    bool unicastResponse = false;
};

// Meaningful fields by type: Ptr target; Srv priority, weight, port, target; Txt txt (empty list =
// zero length record = one empty string, RFC 6763 section 6.1); A/Aaaa address; other rdata
// (verbatim).
struct NETVFS_EXPORT Record {
    QByteArray name;
    quint16 type = 0;
    quint16 cls = ClassIn;
    bool cacheFlush = false;
    quint32 ttl = 0;
    QByteArray target;
    quint16 priority = 0;
    quint16 weight = 0;
    quint16 port = 0;
    QList<QByteArray> txt;
    QHostAddress address;
    QByteArray rdata;

    // Qt 5 QHostAddress has no move ctor; Qt aborts on alloc failure, so moves are noexcept in
    // effect.
    Record() = default;
    Record(const Record &other) = default;
    Record &operator=(const Record &other) = default;
    Record(Record &&other) noexcept = default;
    Record &operator=(Record &&other) noexcept = default;
    ~Record() = default;
};

struct NETVFS_EXPORT Message {
    quint16 id = 0;
    quint16 flags = 0;
    QVector<Question> questions;
    QVector<Record> answers;
    QVector<Record> authority;
    QVector<Record> additional;

    bool isResponse() const { return (flags & FlagResponse) != 0; }
    int opcode() const { return (flags >> 11) & 0x0F; }
    int rcode() const { return flags & 0x0F; }
};

// On failure returns false, leaves `*out` empty, sets short English `error` if given.
NETVFS_EXPORT bool decode(const QByteArray &packet, Message *out, QString *error = nullptr);

// Names compressed unless `compress` false (SRV targets never, RFC 2782). Empty result when
// unrepresentable: label > 63, name > 255, TXT string > 255, wrong address family, packet >
// MaxPacketSize.
NETVFS_EXPORT QByteArray encode(const Message &message, bool compress = true);

// `*ok` false for malformed escape or empty label.
NETVFS_EXPORT QList<QByteArray> splitName(const QByteArray &name, bool *ok = nullptr);
NETVFS_EXPORT QByteArray joinName(const QList<QByteArray> &labels);
// DNS compares names case-insensitively (RFC 1035 2.3.3).
NETVFS_EXPORT QByteArray canonicalName(const QByteArray &name);

}
#endif
