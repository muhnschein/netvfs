// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_WIRE_H
#define NETVFS_TEST_WIRE_H

#include "error.h"
#include "unixfd.h"

#include <QtCore/QByteArray>
#include <QtCore/QMetaType>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QVariant>
#include <QtCore/QVector>

#include <memory>
#include <vector>

struct DBusMessage;
struct DBusMessageIter;

// The consumer side of SPEC-v2 XB-8 for the black-box tests of the bridge
// (design §4.3): a client that speaks peer-to-peer D-Bus through libdbus,
// independent of the bridge's own zbus, so that the tests show the two
// interoperate (EXTERNAL authentication, Unix fd passing, error replies with
// their a{sv}). QtDBus cannot be that client: in Qt 5.6 a peer-to-peer
// QDBusConnection never negotiates Unix fd passing
// (QDBusConnectionPrivate::setPeer leaves the capabilities at 0), so the "h"
// arguments of Upload and Download (XB-11) could not be sent.
//
// This file holds the message codec: arguments of replies and signals are
// decoded into plain Qt values, calls are written with WireWriter. It is the
// codec of the C++ bridge of netvfs 0.4, which libdbus served.
namespace NetVfs::BridgeTest {

// Owning pointer to a libdbus message.
struct MessageUnref {
    void operator()(DBusMessage *message) const;
};
using MessagePtr = std::unique_ptr<DBusMessage, MessageUnref>;

struct DecodeLimits {
    int maxDepth = 8;                 // nested containers
    int maxElements = 4096;           // per array or map
};

// Decodes every argument of `message`:
//   y -> uint (0..255)   b -> bool      n, i -> int     q, u -> uint
//   x -> qlonglong       t -> qulonglong d -> double    s, o, g -> QString
//   h -> UnixFd          ay -> QByteArray   as -> QStringList
//   a{s?} -> QVariantMap  other arrays and structs -> QVariantList
//   v -> the decoded inner value
// Fails with ProtocolError beyond the limits or on dict keys that are not
// strings.
Result decodeArguments(DBusMessage *message, QVariantList *out, const DecodeLimits &limits = DecodeLimits());

// Appends values to a message (a method call). Returns false
// once anything failed (out of memory, invalid value); later calls are no-ops.
class WireWriter
{
public:
    explicit WireWriter(DBusMessage *message);
    ~WireWriter();
    WireWriter(const WireWriter &) = delete;
    WireWriter &operator=(const WireWriter &) = delete;

    WireWriter &byte(quint8 v);
    WireWriter &boolean(bool v);
    WireWriter &int32(qint32 v);
    WireWriter &uint16(quint16 v);
    WireWriter &uint32(quint32 v);
    WireWriter &int64(qint64 v);
    WireWriter &string(const QString &v);
    WireWriter &bytes(const QByteArray &v);
    WireWriter &strings(const QStringList &v);
    WireWriter &unixFd(int fd);
    // a{sv}; see variant() for the value types.
    WireWriter &variantMap(const QVariantMap &v);
    // v: bool b, int i, uint u, qlonglong x, qulonglong t, double d,
    // QString s, QByteArray ay, QStringList as, QVariantMap a{sv},
    // QVariantList av. Anything else fails.
    WireWriter &variant(const QVariant &v);

    // Containers: openStruct()/openArray() ... close().
    WireWriter &openStruct();
    WireWriter &openArray(const char *elementSignature);
    WireWriter &close();

    bool ok() const { return m_ok; }

private:
    DBusMessageIter *top();
    void open(int type, const char *signature);
    template <typename T>
    void appendBasic(int type, const T *value);   // the basic value libdbus copies
    bool appendVariantValue(const QVariant &v);

    std::vector<std::unique_ptr<DBusMessageIter>> m_stack;
    bool m_ok = true;
};

// D-Bus signature of a value accepted by WireWriter::variant(); empty if none.
QByteArray variantSignature(const QVariant &v);

} // namespace NetVfs::BridgeTest

#endif
