// SPDX-License-Identifier: LGPL-2.1-or-later
#include "location.h"

#include "accountsession.h"
#include "bridgelog.h"
#include "names.h"
#include "paths.h"
#include "url.h"

#include <Accounts/Manager>

#include <QtCore/QPointer>

namespace NetVfs::Bridge {

QString LocationSpec::hostKey() const
{
    return provider + QStringLiteral("://") + params.host.toLower() + QLatin1Char(':') + QString::number(params.port);
}

QVariantMap LocationSpec::info() const
{
    QVariantMap map;
    map.insert(QStringLiteral("kind"), kind == LocationKind::Account ? QStringLiteral("account")
                                                                       : QStringLiteral("adhoc"));
    map.insert(QStringLiteral("host"), params.host);
    if (params.port > 0)
        map.insert(QStringLiteral("port"), params.port);
    if (!params.username.isEmpty())
        map.insert(QStringLiteral("user"), params.username);
    map.insert(QStringLiteral("path"), Names::encode(startPath));
    if (const QString url = Url::format(params, startPath); !url.isEmpty())
        map.insert(QStringLiteral("url"), url);
    if (kind == LocationKind::Account) {
        map.insert(QStringLiteral("accountId"), accountId);
        if (attention != Attention::None)
            map.insert(QStringLiteral("attention"), attentionToString(attention));
    }
    return map;
}

AccountDirectory::~AccountDirectory() = default;

// ----------------------------------------------------------- libaccounts

class LibAccountsDirectory::Private
{
public:
    Accounts::Manager manager;
};

LibAccountsDirectory::LibAccountsDirectory(QObject *parent)
    : AccountDirectory(parent)
    , d(std::make_unique<Private>())
{
    const Accounts::Manager *m = &d->manager;
    connect(m, &Accounts::Manager::accountCreated, this, &AccountDirectory::changed);
    connect(m, &Accounts::Manager::accountRemoved, this, &AccountDirectory::changed);
    connect(m, &Accounts::Manager::accountUpdated, this, &AccountDirectory::changed);
    connect(m, &Accounts::Manager::enabledEvent, this, &AccountDirectory::changed);
}

LibAccountsDirectory::~LibAccountsDirectory() = default;

QVector<AccountLocation> LibAccountsDirectory::filesAccounts()
{
    // XA-1: enabled accounts whose Files service is enabled.
    QVector<AccountLocation> result;
    const AccountStore store(&d->manager);
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
    return result;
}

void LibAccountsDirectory::fetch(int accountId, const Fetched &done)
{
    // XA-4: refuses (SecurityPolicy) a configuration the Files service may not use.
    AccountSession *session = AccountSession::open(accountId, Service::Files, this);
    auto finished = std::make_shared<bool>(false);
    QPointer<AccountSession> guard(session);
    connect(session, &AccountSession::ready, this, [guard, done, finished]() {
        if (!guard || *finished)
            return;
        *finished = true;
        done(Result::success(), guard->params(), guard->credentials());
        guard->releaseCredentials();   // SEC-5: the connection keeps no copy beyond establish
        guard->deleteLater();
    });
    connect(session, &AccountSession::failed, this, [guard, done, finished](const Result &result) {
        if (!guard || *finished)
            return;
        *finished = true;
        done(result, ConnectionParams(), Credentials());
        guard->deleteLater();
    });
}

void LibAccountsDirectory::setAttention(int accountId, Attention attention, const QString &seenPin)
{
    if (const Result r = AccountStore(&d->manager).setAttention(accountId, Service::Files, attention, seenPin); !r.ok())
        qCWarning(lcNetVfsBridge) << "Cannot record the attention state:" << r.toString();
}

} // namespace NetVfs::Bridge
