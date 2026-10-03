// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountstore.h"
#include "logging.h"

#include <Accounts/Account>
#include <Accounts/Manager>
#include <Accounts/Service>

#include <algorithm>

namespace NetVfs {

namespace Keys {
const char Host[] = "netvfs/host";
const char Port[] = "netvfs/port";
const char Username[] = "netvfs/username";
const char Attention[] = "netvfs/attention";
const char BackupsPath[] = "backups_path";
const char FilesRoot[] = "files_root";
const char DefaultCredentialsUsername[] = "default_credentials_username";
const char CredentialsNeedUpdate[] = "CredentialsNeedUpdate";
const char CredentialsNeedUpdateFrom[] = "CredentialsNeedUpdateFrom";
const char HostKeySeen[] = "host_key_seen";

QString providerKey(const QString &provider, const QString &key)
{
    return QStringLiteral("netvfs/%1/%2").arg(provider, key);
}
} // namespace Keys

const char DefaultBackupsPath[] = "Sailfish OS/Backups";
const char CredentialsApplication[] = "netvfs";
const char CredentialsName[] = "default";
const char FilesServiceType[] = "netvfs-files";

namespace {
const char AttentionAuthFailed[] = "auth-failed";
const char AttentionIdentityChanged[] = "server-identity-changed";

Result notFound(int accountId)
{
    return Result(Error::NotFound, QStringLiteral("Account %1 does not exist").arg(accountId));
}

// The value of `key` in the provider's `service`; empty when the service is
// not installed. Leaves the global service selected.
QString serviceValue(const Accounts::Manager *manager, Accounts::Account *account, Service service, const char *key,
                     bool *enabled)
{
    QString value;
    *enabled = false;
    if (const Accounts::Service s = manager->service(serviceName(account->providerName(), service)); s.isValid()) {
        account->selectService(s);
        value = account->value(QLatin1String(key)).toString();
        *enabled = account->isEnabled();
        account->selectService(Accounts::Service());
    }
    return value;
}

Result sync(Accounts::Account *account)
{
    if (!account->syncAndBlock())
        return Result(Error::Internal, QStringLiteral("Cannot write the accounts database"));
    return Result::success();
}
} // namespace

QString attentionToString(Attention attention)
{
    switch (attention) {
    case Attention::AuthFailed:
        return QLatin1String(AttentionAuthFailed);
    case Attention::ServerIdentityChanged:
        return QLatin1String(AttentionIdentityChanged);
    case Attention::None:
        break;
    }
    return QString();
}

Attention attentionFromString(const QString &value)
{
    if (value == QLatin1String(AttentionAuthFailed))
        return Attention::AuthFailed;
    if (value == QLatin1String(AttentionIdentityChanged))
        return Attention::ServerIdentityChanged;
    return Attention::None;
}

Attention attentionForError(Error error)
{
    switch (error) {
    case Error::AuthFailed:
        return Attention::AuthFailed;
    case Error::ServerIdentityChanged:
    case Error::ServerIdentityUnknown:
        return Attention::ServerIdentityChanged;
    default:
        return Attention::None;
    }
}

QString backupServiceName(const QString &provider)
{
    return serviceName(provider, Service::Backup);
}

QString filesServiceName(const QString &provider)
{
    return serviceName(provider, Service::Files);
}

AccountStore::AccountStore(Accounts::Manager *manager)
    : m_manager(manager)
{
}

Result AccountStore::load(int accountId, Service service, AccountConfig *out) const
{
    Accounts::Account *account = m_manager->account(accountId);  // owned by the manager
    if (!account)
        return notFound(accountId);

    AccountConfig config;
    config.accountId = accountId;
    config.provider = account->providerName();
    config.displayName = account->displayName();
    config.service = service;

    account->selectService(Accounts::Service());
    config.enabled = account->isEnabled();
    config.credentialsId = account->credentialsId();
    config.attention = attentionFromString(account->value(QLatin1String(Keys::Attention)).toString());
    config.credentialsNeedUpdate = account->value(QLatin1String(Keys::CredentialsNeedUpdate)).toBool();

    ConnectionParams &params = config.params;
    params.provider = config.provider;
    params.host = account->value(QLatin1String(Keys::Host)).toString();
    params.port = account->value(QLatin1String(Keys::Port)).toInt();
    params.username = account->value(QLatin1String(Keys::Username)).toString();
    const QString prefix = QStringLiteral("netvfs/%1/").arg(config.provider);
    for (const QString &key : account->allKeys()) {
        if (key.startsWith(prefix))
            params.options.insert(key.mid(prefix.size()), account->value(key));
    }
    config.securityProfile = securityProfile(params);
    config.insecureAllowed = params.flag(QLatin1String(OptionKeys::AllowInsecure));

    bool backupEnabled = false;
    bool filesEnabled = false;
    config.backupsPath = serviceValue(m_manager, account, Service::Backup, Keys::BackupsPath, &backupEnabled);
    if (config.backupsPath.trimmed().isEmpty())
        config.backupsPath = QLatin1String(DefaultBackupsPath);
    config.filesRoot = serviceValue(m_manager, account, Service::Files, Keys::FilesRoot, &filesEnabled).trimmed();
    config.serviceEnabled = config.enabled && (service == Service::Backup ? backupEnabled : filesEnabled);

    if (params.host.isEmpty())
        return Result(Error::Internal, QStringLiteral("Account %1 has no server").arg(accountId));

    if (out)
        *out = config;
    return Result::success();
}

QList<int> AccountStore::filesAccounts() const
{
    QList<int> ids;
    for (const Accounts::AccountId id : m_manager->accountList(QLatin1String(FilesServiceType))) {
        Accounts::Account *account = m_manager->account(id);   // owned by the manager
        if (!account)
            continue;
        account->selectService(Accounts::Service());
        if (!account->isEnabled())
            continue;
        bool filesEnabled = false;
        serviceValue(m_manager, account, Service::Files, Keys::FilesRoot, &filesEnabled);
        if (filesEnabled)
            ids << static_cast<int>(id);
    }
    std::sort(ids.begin(), ids.end());
    return ids;
}

Result AccountStore::setAttention(int accountId, Service service, Attention attention,
                                  const QString &seenIdentityPin) const
{
    if (attention == Attention::None)
        return clearAttention(accountId);

    Accounts::Account *account = m_manager->account(accountId);  // owned by the manager
    if (!account)
        return notFound(accountId);

    const QString provider = account->providerName();
    account->selectService(Accounts::Service());
    account->setValue(QLatin1String(Keys::Attention), attentionToString(attention));
    account->setValue(QLatin1String(Keys::CredentialsNeedUpdate), true);
    account->setValue(QLatin1String(Keys::CredentialsNeedUpdateFrom), serviceName(provider, service));
    if (!seenIdentityPin.isEmpty())
        account->setValue(Keys::providerKey(provider, QLatin1String(Keys::HostKeySeen)), seenIdentityPin);
    qCDebug(lcNetVfsCore) << "Account" << accountId << "needs attention:" << attentionToString(attention);
    return sync(account);
}

Result AccountStore::clearAttention(int accountId) const
{
    Accounts::Account *account = m_manager->account(accountId);  // owned by the manager
    if (!account)
        return notFound(accountId);

    account->selectService(Accounts::Service());
    account->remove(QLatin1String(Keys::Attention));
    account->remove(QLatin1String(Keys::CredentialsNeedUpdateFrom));
    account->remove(Keys::providerKey(account->providerName(), QLatin1String(Keys::HostKeySeen)));
    account->setValue(QLatin1String(Keys::CredentialsNeedUpdate), false);
    return sync(account);
}

} // namespace NetVfs
