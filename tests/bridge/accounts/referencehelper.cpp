// SPDX-License-Identifier: LGPL-2.1-or-later
// The C++ netvfs-accounts (the bridge's accountshelper.cpp at b143680), with
// its name, the account record (now in referencedecoder.h) and the answer
// header of today: the golden reference of the Rust helper's answers.
#include "referencehelper.h"

#include "accountstore.h"
#include "paths.h"
#include "referencedecoder.h"

#include <Accounts/Manager>

#include <QtCore/QDataStream>

namespace NetVfs {
namespace Test {

namespace {

constexpr QDataStream::Version StreamVersion = QDataStream::Qt_5_6;

void writeParams(QDataStream &s, const ConnectionParams &p)
{
    s << p.provider << p.host << qint32(p.port) << p.username << p.options << qint32(p.connectTimeoutMs)
      << qint32(p.requestTimeoutMs);
}

class Answer
{
public:
    explicit Answer(const Result &result) : m_stream(&m_bytes, QIODevice::WriteOnly)
    {
        m_stream.setVersion(StreamVersion);
        m_stream << qint32(result.error()) << result.message();
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
    // refused before the secret is read.
    if (const Result r = checkServicePolicy(config.params, Service::Files); !r.ok())
        return failure(r);
    Answer answer(Result::success());
    writeParams(answer.stream(), config.params);
    answer.stream() << quint32(config.credentialsId) << secretOptional(config.params);
    return answer.bytes();
}

QByteArray serveAttention(const AccountStore &store, const QString &id, const QString &state, const QString &pin)
{
    const Attention attention = attentionFromString(state);
    if (attention == Attention::None)
        return failure(Result(Error::Unsupported, QStringLiteral("Unknown attention state")));
    AccountConfig config;
    if (const Result r = loadListed(store, id, &config); !r.ok())
        return failure(r);
    return failure(store.setAttention(config.accountId, Service::Files, attention, pin));
}

} // namespace

QByteArray referenceServe(Accounts::Manager *manager, const QStringList &arguments)
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

} // namespace Test
} // namespace NetVfs
