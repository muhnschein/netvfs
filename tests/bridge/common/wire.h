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

namespace NetVfs::BridgeTest {

struct MessageUnref {
    void operator()(DBusMessage *message) const;
};
using MessagePtr = std::unique_ptr<DBusMessage, MessageUnref>;

struct DecodeLimits {
    int maxDepth = 8;
    int maxElements = 4096;
};

Result decodeArguments(DBusMessage *message, QVariantList *out, const DecodeLimits &limits = DecodeLimits());

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
    WireWriter &variantMap(const QVariantMap &v);
    WireWriter &variant(const QVariant &v);

    WireWriter &openStruct();
    WireWriter &openArray(const char *elementSignature);
    WireWriter &close();

    bool ok() const { return m_ok; }

private:
    DBusMessageIter *top();
    void open(int type, const char *signature);
    template <typename T>
    void appendBasic(int type, const T *value);
    bool appendVariantValue(const QVariant &v);

    std::vector<std::unique_ptr<DBusMessageIter>> m_stack;
    bool m_ok = true;
};

QByteArray variantSignature(const QVariant &v);

}

#endif
