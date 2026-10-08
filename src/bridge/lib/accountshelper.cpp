// SPDX-License-Identifier: LGPL-2.1-or-later
// The protocol of netvfs-accounts (XB-2a), linked by the helper and the bridge.
#include "accountshelper.h"

#include "paths.h"

#include <Accounts/Manager>

#include <QtCore/QDataStream>

namespace NetVfs::Bridge {

namespace {

const char HelperVariable[] = "NETVFS_ACCOUNTS_HELPER";
const char InstalledHelper[] = "/usr/libexec/netvfs/netvfs-accounts";
const char AnswerMagic[] = "netvfs-accounts/1";
constexpr QDataStream::Version StreamVersion = QDataStream::Qt_5_6;
constexpr int MaxAccounts = 10000;

void writeParams(QDataStream &s, const ConnectionParams &p)
{
    s << p.provider << p.host << qint32(p.port) << p.username << p.options << qint32(p.connectTimeoutMs)
      << qint32(p.requestTimeoutMs);
}

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

class Answer
{
public:
    explicit Answer(const Result &result) : m_stream(&m_bytes, QIODevice::WriteOnly)
    {
        m_stream.setVersion(StreamVersion);
        m_stream << QByteArray(AnswerMagic) << qint32(result.error()) << result.message();
    }
    QDataStream &stream() { return m_stream; }
    QByteArray bytes() const { return m_bytes; }

private:
    QByteArray m_bytes;
    QDataStream m_stream;
};

QByteArray failure(const Result &result)
{
    return Answer(result).bytes();
}

Result malformed()
{
    return Result(Error::ProtocolError, QStringLiteral("netvfs-accounts gave a malformed answer"));
}

// Reads the header; the helper's result, with `stream` at the payload.
Result readHeader(QDataStream &stream)
{
    stream.setVersion(StreamVersion);
    QByteArray magic;
    qint32 error = 0;
    QString message;
    stream >> magic >> error >> message;
    if (stream.status() != QDataStream::Ok || magic != AnswerMagic || error < 0
            || error > qint32(Error::NotModified))
        return malformed();
    return Result(Error(error), message);
}

Result databaseUsable(const Accounts::Manager *manager)
{
    // libaccounts reports an unreadable database only through lastError()
    // and then lists nothing. On Sailfish OS only the group `privileged` can
    // read it, which this helper gets from its setgid bit.
    if (const Accounts::Error error = manager->lastError(); error.type() != Accounts::Error::NoError)
        return Result(Error::PermissionDenied,
                      QStringLiteral("Cannot open the accounts database (libaccounts error %1 %2). "
                                     "Is netvfs-accounts installed setgid privileged?")
                          .arg(int(error.type()))
                          .arg(error.message()));
    return Result::success();
}

// The listed account `id` (enabled, Files service enabled), for Files.
Result loadListed(const AccountStore &store, const QString &id, AccountConfig *config)
{
    bool valid = false;
    const int accountId = id.toInt(&valid);
    if (!valid || accountId <= 0 || !store.filesAccounts().contains(accountId))
        return Result(Error::NotFound, QStringLiteral("No such account"));
    return store.load(accountId, Service::Files, config);
}

QByteArray serveList(const AccountStore &store)
{
    // XA-1: enabled accounts whose Files service is enabled.
    QVector<AccountLocation> result;
    for (const int id : store.filesAccounts()) {
        AccountConfig config;
        if (!store.load(id, Service::Files, &config).ok())
            continue;
        AccountLocation location;
        location.accountId = id;
        location.provider = config.provider;
        location.displayName = config.displayName;
        location.params = config.params;
        location.attention = config.attention;
        if (QString normalized; Paths::normalize(config.filesRoot, &normalized).ok())
            location.filesRoot = normalized;
        result.append(location);
    }
    Answer answer(Result::success());
    answer.stream() << qint32(result.size());
    for (const AccountLocation &a : result) {
        answer.stream() << qint32(a.accountId) << a.provider << a.displayName;
        writeParams(answer.stream(), a.params);
        answer.stream() << a.filesRoot << qint32(a.attention);
    }
    return answer.bytes();
}

QByteArray serveFiles(const AccountStore &store, const QString &id)
{
    AccountConfig config;
    if (const Result r = loadListed(store, id, &config); !r.ok())
        return failure(r);
    // XA-4: refused before the secret is read.
    if (const Result r = checkServicePolicy(config.params, Service::Files); !r.ok())
        return failure(r);
    const ConnectionParams params = paramsForService(config.params, Service::Files);
    Answer answer(Result::success());
    writeParams(answer.stream(), params);
    answer.stream() << quint32(config.credentialsId) << secretOptional(params);
    return answer.bytes();
}

QByteArray serveAttention(const AccountStore &store, const QString &id, const QString &state, const QString &pin)
{
    // XB-14 records attention; clearing it is the update flow's (Settings).
    const Attention attention = attentionFromString(state);
    if (attention == Attention::None)
        return failure(Result(Error::Unsupported, QStringLiteral("Unknown attention state")));
    AccountConfig config;
    if (const Result r = loadListed(store, id, &config); !r.ok())
        return failure(r);
    return failure(store.setAttention(config.accountId, Service::Files, attention, pin));
}

} // namespace

namespace AccountsHelper {

QString path()
{
    if (qEnvironmentVariableIsSet(HelperVariable))
        return QString::fromLocal8Bit(qgetenv(HelperVariable));
    return QLatin1String(InstalledHelper);
}

QByteArray serve(Accounts::Manager *manager, const QStringList &arguments)
{
    if (const Result r = databaseUsable(manager); !r.ok())
        return failure(r);
    const AccountStore store(manager);
    const QString command = arguments.value(0);
    if (command == QLatin1String("list") && arguments.size() == 1)
        return serveList(store);
    if (command == QLatin1String("files") && arguments.size() == 2)
        return serveFiles(store, arguments.at(1));
    if (command == QLatin1String("attention") && (arguments.size() == 3 || arguments.size() == 4))
        return serveAttention(store, arguments.at(1), arguments.at(2), arguments.value(3));
    return failure(Result(Error::Unsupported, QStringLiteral("Usage: netvfs-accounts list | files <id> | "
                                                             "attention <id> <state> [pin]")));
}

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

} // namespace AccountsHelper

} // namespace NetVfs::Bridge
