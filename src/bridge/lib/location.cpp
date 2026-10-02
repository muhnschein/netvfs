// SPDX-License-Identifier: LGPL-2.1-or-later
#include "location.h"

#include "accountsession.h"
#include "bridgelog.h"
#include "names.h"
#include "paths.h"
#include "url.h"

#include <Accounts/Account>
#include <Accounts/Manager>
#include <Accounts/Service>

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

const char LibAccountsDirectory::FilesServiceType[] = "netvfs-files";

namespace {

QString filesServiceName(const QString &provider)
{
    return provider + QStringLiteral("-files");
}

// The account's Files service, if it has one and it is enabled.
bool filesServiceEnabled(const Accounts::Manager *manager, Accounts::Account *account, QString *filesRoot)
{
    const Accounts::Service service = manager->service(filesServiceName(account->providerName()));
    if (!service.isValid())
        return false;
    account->selectService(service);
    const bool enabled = account->isEnabled();
    *filesRoot = account->value(QStringLiteral("files_root")).toString();
    account->selectService(Accounts::Service());
    return enabled && account->isEnabled();
}

// XA-4 adapter: the accounts work changes this call to
// AccountSession::open(accountId, Service::Files, parent).
AccountSession *openFilesSession(int accountId, QObject *parent)
{
    return AccountSession::open(accountId, parent);
}

} // namespace

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
    QVector<AccountLocation> result;
    const Accounts::AccountIdList ids = d->manager.accountList();
    for (const Accounts::AccountId id : ids) {
        Accounts::Account *account = d->manager.account(id);   // owned by the manager
        QString filesRoot;
        if (!account || !filesServiceEnabled(&d->manager, account, &filesRoot))
            continue;
        AccountConfig config;
        if (!AccountStore(&d->manager).load(static_cast<int>(id), &config).ok())
            continue;
        AccountLocation location;
        location.accountId = static_cast<int>(id);
        location.provider = config.provider;
        location.displayName = config.displayName;
        location.params = config.params;
        location.attention = config.attention;
        if (QString normalized; Paths::normalize(filesRoot, &normalized).ok())
            location.filesRoot = normalized;
        result.append(location);
    }
    return result;
}

void LibAccountsDirectory::fetch(int accountId, const Fetched &done)
{
    AccountSession *session = openFilesSession(accountId, this);
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
    if (const Result r = AccountStore(&d->manager).setAttention(accountId, attention, seenPin); !r.ok())
        qCWarning(lcNetVfsBridge) << "Cannot record the attention state:" << r.toString();
}

} // namespace NetVfs::Bridge
