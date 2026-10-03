// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DNSMESSAGE_H
#define NETVFS_DNSMESSAGE_H

#include "netvfs_global.h"

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtNetwork/QHostAddress>

// SPEC-v2 XD-1: the DNS wire format as far as multicast DNS service discovery
// (RFC 6762, RFC 6763) needs it: questions and the record types A, AAAA, PTR,
// SRV and TXT. No sockets, no clock: a pure encoder and decoder so that it can
// be unit tested and fuzzed (tests/fuzz/fuzz_dns_message.cpp).
//
// decode() parses UNTRUSTED network input. It never reads out of bounds, never
// follows a compression pointer forward (so pointer loops cannot exist), caps
// names at 255 bytes on the wire and labels at 63, and rejects a packet whose
// record counts cannot fit into its size. Anything malformed rejects the whole
// message; there is no partial result.
//
// Names are kept in presentation form: labels joined by '.', a '.' or '\' inside
// a label written as "\." and "\\", control bytes as "\DDD" (decimal). No
// trailing dot; the root name is empty. Bytes >= 0x80 (UTF-8) and spaces are
// kept as they are, so "My NAS._smb._tcp.local" reads naturally. Use
// splitName()/joinName() to get at the labels, canonicalName() to compare.
namespace NetVfs::Dns {

constexpr int HeaderSize = 12;
constexpr int MaxPacketSize = 9000;        // RFC 6762 section 17
constexpr int MaxLabelLength = 63;
constexpr int MaxNameLength = 255;         // wire form, including length bytes and the root
constexpr int MaxRecords = 512;            // questions + records per message accepted by decode()

// Record types (RFC 1035, 3596, 2782).
constexpr quint16 TypeA = 1;
constexpr quint16 TypePtr = 12;
constexpr quint16 TypeTxt = 16;
constexpr quint16 TypeAaaa = 28;
constexpr quint16 TypeSrv = 33;
constexpr quint16 TypeAny = 255;

constexpr quint16 ClassIn = 1;

// Header flag bits (the 16 bit flags word).
constexpr quint16 FlagResponse = 0x8000;
constexpr quint16 FlagAuthoritative = 0x0400;
constexpr quint16 FlagTruncated = 0x0200;

struct NETVFS_EXPORT Question {
    QByteArray name;
    quint16 type = 0;
    quint16 cls = ClassIn;
    bool unicastResponse = false;      // QU bit (RFC 6762 section 5.4)
};

// One resource record. Which fields are meaningful depends on `type`:
//   TypePtr          target
//   TypeSrv          priority, weight, port, target
//   TypeTxt          txt (the character strings; an empty list and a zero length record both
//                    mean one empty string, RFC 6763 section 6.1)
//   TypeA, TypeAaaa  address
//   anything else    rdata (raw, not interpreted; decoded and encoded verbatim)
struct NETVFS_EXPORT Record {
    QByteArray name;
    quint16 type = 0;
    quint16 cls = ClassIn;
    bool cacheFlush = false;           // top bit of the class (RFC 6762 section 10.2)
    quint32 ttl = 0;                   // seconds; 0 is a goodbye (RFC 6762 section 10.1)
    QByteArray target;
    quint16 priority = 0;
    quint16 weight = 0;
    quint16 port = 0;
    QList<QByteArray> txt;
    QHostAddress address;
    QByteArray rdata;

    // Qt 5's QHostAddress has no move constructor, so a move copies its data.
    // Qt reports allocation failure by aborting, never by throwing, which
    // makes the moves noexcept in effect; containers rely on it.
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

// Parses `packet`. On failure returns false, leaves `*out` empty and, when
// `error` is not null, sets a short English reason (for debug logs and tests).
NETVFS_EXPORT bool decode(const QByteArray &packet, Message *out, QString *error = nullptr);

// Serialises `message`; names are compressed unless `compress` is false (SRV
// targets are never compressed, RFC 2782). Returns an empty array when the
// message cannot be represented: a label over 63 bytes, a name over 255, a TXT
// string over 255 bytes, an address of the wrong family for its type, or a
// packet over MaxPacketSize.
NETVFS_EXPORT QByteArray encode(const Message &message, bool compress = true);

// Splits a presentation name into unescaped labels. `*ok` is false for a
// malformed escape or an empty label ("a..b"). The empty name has no labels.
NETVFS_EXPORT QList<QByteArray> splitName(const QByteArray &name, bool *ok = nullptr);
// Inverse of splitName(): escapes and joins.
NETVFS_EXPORT QByteArray joinName(const QList<QByteArray> &labels);
// ASCII lower case; DNS compares names case-insensitively (RFC 1035 2.3.3).
NETVFS_EXPORT QByteArray canonicalName(const QByteArray &name);

// TXT strings "key=value" (RFC 6763 section 6): value of `key` (compared case
// insensitively), or `fallback` if absent. A key without '=' yields an empty
// value. The first occurrence wins.
NETVFS_EXPORT QByteArray txtValue(const QList<QByteArray> &txt, const QByteArray &key,
                                  const QByteArray &fallback = QByteArray());
NETVFS_EXPORT bool txtHasKey(const QList<QByteArray> &txt, const QByteArray &key);

} // namespace NetVfs::Dns

#endif
