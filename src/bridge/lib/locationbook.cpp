// SPDX-License-Identifier: LGPL-2.1-or-later
#include "serverparts.h"

#include "backendloader.h"

namespace NetVfs::Bridge {

namespace {

QString accountLocationId(int accountId)
{
    return QStringLiteral("account:") + QString::number(accountId);
}

LocationSpec specFor(const AccountLocation &account)
{
    LocationSpec spec;
    spec.id = accountLocationId(account.accountId);
    spec.kind = LocationKind::Account;
    spec.accountId = account.accountId;
    spec.provider = account.provider;
    spec.name = account.displayName;
    spec.params = account.params;
    spec.startPath = account.filesRoot;
    spec.attention = account.attention;
    return spec;
}

bool sameConnection(const ConnectionParams &a, const ConnectionParams &b)
{
    return a.provider == b.provider && a.host == b.host && a.port == b.port && a.username == b.username
        && a.options == b.options;
}

// The injected directory belongs to the book; without one the accounts
// database is read.
std::unique_ptr<AccountDirectory> directoryFor(AccountDirectory *injected)
{
    if (injected)
        return std::unique_ptr<AccountDirectory>(injected);
    return std::make_unique<LibAccountsDirectory>();
}

QString knownHostsFileOf(const BridgeConfig &config)
{
    return config.knownHostsFile.isEmpty() ? KnownHosts::defaultFilePath(config.consumer.id)
                                           : config.knownHostsFile;
}

} // namespace

LocationBook::LocationBook(BridgeServer *server, AccountDirectory *injectedAccounts)
    : m_server(server)
    , m_knownHosts(knownHostsFileOf(server->config()))
    , m_connector(std::make_unique<BridgeConnector>(server, &m_knownHosts, server->config().questionTimeoutMs))
    , m_accounts(directoryFor(injectedAccounts))
{
    QObject::connect(m_accounts.get(), &AccountDirectory::changed, server, [this]() { refresh(); });
}

LocationBook::~LocationBook()
{
    wipeAdHocSecrets();
}

void LocationBook::load()
{
    m_accountList = m_accounts->filesAccounts();
}

void LocationBook::refresh()
{
    const QVector<AccountLocation> accounts = m_accounts->filesAccounts();
    QHash<QString, AccountLocation> byId;
    for (const AccountLocation &a : accounts)
        byId.insert(accountLocationId(a.accountId), a);
    for (auto it = m_pools.begin(); it != m_pools.end();) {
        const LocationSpec &spec = it->second->spec();
        const bool account = spec.kind == LocationKind::Account;
        const auto found = byId.constFind(spec.id);
        if (account && (found == byId.constEnd() || !sameConnection(found->params, spec.params)))
            it = m_pools.erase(it);   // removed or changed: new connections use the new settings
        else
            ++it;
    }
    m_accountList = accounts;
    if (m_server->consent() == Consent::Granted)
        m_server->broadcast("LocationsChanged");
}

void LocationBook::revoke()
{
    m_pools.clear();
    wipeAdHocSecrets();
    m_adHoc.clear();
}

void LocationBook::wipeAdHocSecrets()
{
    for (const auto &[id, spec] : m_adHoc) {
        if (spec.adHocCredentials)
            spec.adHocCredentials->wipe();
    }
}

void LocationBook::kick() const
{
    for (const auto &[id, pool] : m_pools)
        pool->kick();
}

void LocationBook::maintain(qint64 nowMs) const
{
    for (const auto &[id, pool] : m_pools)
        pool->maintain(nowMs, m_server->config().connectionIdleMs);
}

QVector<LocationSpec> LocationBook::visible() const
{
    QVector<LocationSpec> result;
    for (const AccountLocation &a : m_accountList)
        result << specFor(a);
    for (const auto &[id, spec] : m_adHoc)
        result << spec;
    return result;
}

bool LocationBook::find(const QString &id, LocationSpec *out) const
{
    for (const AccountLocation &a : m_accountList) {
        if (accountLocationId(a.accountId) == id) {
            *out = specFor(a);
            return true;
        }
    }
    const auto it = m_adHoc.find(id);
    if (it == m_adHoc.end())
        return false;
    *out = it->second;
    return true;
}

Pool *LocationBook::existing(const QString &id) const
{
    const auto it = m_pools.find(id);
    return it == m_pools.end() ? nullptr : it->second.get();
}

Pool *LocationBook::pool(const QString &id, Result *error)
{
    if (m_server->consent() != Consent::Granted) {
        *error = Result(Error::PermissionDenied, QStringLiteral("The user has not allowed this app to use network locations"));
        return nullptr;
    }
    if (Pool *known = existing(id))
        return known;
    LocationSpec spec;
    if (!find(id, &spec)) {
        *error = Result(Error::NotFound, QStringLiteral("No such location"));
        return nullptr;
    }
    if (!BackendLoader::isAvailable(spec.provider)) {
        // XP-5: a missing backend package is Unsupported.
        *error = Result(Error::Unsupported, QStringLiteral("No backend for %1 is installed").arg(spec.provider));
        return nullptr;
    }
    auto created = std::make_unique<Pool>(spec, m_connector.get(), &m_hosts);
    Pool *raw = created.get();
    m_pools[id] = std::move(created);
    return raw;
}

QString LocationBook::reserveAdHocId()
{
    return QStringLiteral("adhoc:") + QString::number(m_nextAdHoc++);
}

QString LocationBook::addAdHoc(const LocationSpec &spec, std::unique_ptr<Pool> pool)
{
    m_adHoc[spec.id] = spec;
    m_pools[spec.id] = std::move(pool);
    m_server->broadcast("LocationsChanged");
    return spec.id;
}

bool LocationBook::forgetAdHoc(const QString &id)
{
    const auto it = m_adHoc.find(id);
    if (it == m_adHoc.end())
        return false;
    // XB-14: forgetting drops the pin, so the next contact asks again.
    m_knownHosts.remove(it->second.hostKey());
    if (it->second.adHocCredentials)
        it->second.adHocCredentials->wipe();
    m_adHoc.erase(it);
    m_pools.erase(id);
    m_server->broadcast("LocationsChanged");
    return true;
}

void LocationBook::disconnect(const QString &id) const
{
    if (Pool *p = existing(id))
        p->stopAll();
}

void LocationBook::closeWorkerHandle(const QString &loc, Worker *worker, quint32 handle) const
{
    if (const Pool *p = existing(loc); !p || !worker || !p->owns(worker))
        return;   // the connection is gone and its handles with it
    Pool::submitTo(worker, TaskContext(), [handle](Backend *, const Result &, Worker *w) {
        if (w)
            w->closeHandle(handle);
        return Result::success();
    });
}

void LocationBook::setAttention(int accountId, Attention attention, const QString &seenPin) const
{
    m_accounts->setAttention(accountId, attention, seenPin);
}

void LocationBook::fetch(int accountId, const AccountDirectory::Fetched &done) const
{
    m_accounts->fetch(accountId, done);
}

} // namespace NetVfs::Bridge
