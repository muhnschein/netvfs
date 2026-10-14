// SPDX-License-Identifier: LGPL-2.1-or-later
// The C++ bridge's side of the netvfs-accounts protocol (XB-2a): the
// reference decoder of the golden tests.
#include "referencedecoder.h"

#include <QtCore/QDataStream>

namespace NetVfs::Test {

namespace {

constexpr QDataStream::Version StreamVersion = QDataStream::Qt_5_6;
constexpr int MaxAccounts = 10000;

void readParams(QDataStream &s, ConnectionParams *p)
{
    qint32 port = 0;
    qint32 connectTimeout = 0;
    qint32 requestTimeout = 0;
    s >> p->provider >> p->host >> port >> p->username >> p->options >> connectTimeout >> requestTimeout;
    p->port = port;
    p->connectTimeoutMs = connectTimeout;
    p->requestTimeoutMs = requestTimeout;
}

Result malformed()
{
    return Result(Error::ProtocolError, QStringLiteral("netvfs-accounts gave a malformed answer"));
}

// Reads the header; the helper's result, with `stream` at the payload.
Result readHeader(QDataStream &stream)
{
    stream.setVersion(StreamVersion);
    qint32 error = 0;
    QString message;
    stream >> error >> message;
    if (stream.status() != QDataStream::Ok || error < 0 || error > qint32(Error::RateLimited))
        return malformed();
    return Result(Error(error), message);
}

} // namespace

Result decodeList(const QByteArray &answer, QVector<AccountLocation> *accounts)
{
    QDataStream stream(answer);
    if (const Result r = readHeader(stream); !r.ok())
        return r;
    qint32 count = 0;
    stream >> count;
    if (count < 0 || count > MaxAccounts)
        return malformed();
    QVector<AccountLocation> result;
    for (qint32 i = 0; i < count && stream.status() == QDataStream::Ok; ++i) {
        AccountLocation a;
        qint32 id = 0;
        qint32 attention = 0;
        stream >> id >> a.provider >> a.displayName;
        readParams(stream, &a.params);
        stream >> a.filesRoot >> attention;
        if (attention < qint32(Attention::None) || attention > qint32(Attention::ServerIdentityChanged))
            return malformed();
        a.accountId = id;
        a.attention = Attention(attention);
        result.append(a);
    }
    if (stream.status() != QDataStream::Ok || !stream.atEnd())
        return malformed();
    *accounts = result;
    return Result::success();
}

Result decodeFiles(const QByteArray &answer, FilesAccess *access)
{
    QDataStream stream(answer);
    if (const Result r = readHeader(stream); !r.ok())
        return r;
    FilesAccess result;
    readParams(stream, &result.params);
    stream >> result.credentialsId >> result.secretOptional;
    if (stream.status() != QDataStream::Ok || !stream.atEnd())
        return malformed();
    *access = result;
    return Result::success();
}

Result decodeStatus(const QByteArray &answer)
{
    QDataStream stream(answer);
    const Result r = readHeader(stream);
    if (r.ok() && !stream.atEnd())
        return malformed();
    return r;
}

} // namespace NetVfs::Test
