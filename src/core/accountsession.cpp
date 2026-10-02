// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountsession.h"
#include "backendloader.h"
#include "logging.h"
#include "secretsource.h"

#include <Accounts/Manager>

#include <QtCore/QTimer>

#include <memory>

namespace NetVfs {

AccountSession *AccountSession::open(int accountId, Service service, QObject *parent)
{
    auto manager = std::make_unique<Accounts::Manager>();
    auto session = std::make_unique<AccountSession>(manager.get(), std::make_unique<SignonSecretSource>().release(),
                                                    parent);
    manager.release()->setParent(session.get());
    // Deferred so callers can connect to ready()/failed() first.
    AccountSession *raw = session.release();   // owned by `parent` (Qt ownership)
    QTimer::singleShot(0, raw, [raw, accountId, service]() { raw->start(accountId, service); });
    return raw;
}

AccountSession::AccountSession(Accounts::Manager *manager, SecretSource *secrets, QObject *parent)
    : QObject(parent)
    , m_manager(manager)
    , m_secrets(secrets)
{
    m_secrets->setParent(this);
    connect(m_secrets, &SecretSource::fetched, this, &AccountSession::onFetched);
    connect(m_secrets, &SecretSource::failed, this, &AccountSession::onFailed);
}

AccountSession::~AccountSession()
{
    releaseCredentials();
}

void AccountSession::start(int accountId, Service service)
{
    if (const Result r = AccountStore(m_manager).load(accountId, service, &m_config); !r.ok()) {
        emit failed(r);
        return;
    }
    // XA-4: refused before the secret is read.
    if (const Result r = checkServicePolicy(m_config.params, service); !r.ok()) {
        qCDebug(lcNetVfsCore) << "Account" << accountId << "refused for" << serviceId(service) << r.toString();
        emit failed(r);
        return;
    }
    m_config.params = paramsForService(m_config.params, service);
    m_secrets->setSecretOptional(secretOptional(m_config.params));   // XA-7
    m_secrets->fetch(m_config.credentialsId);
}

Backend *AccountSession::backend()
{
    if (!m_backend)
        m_backend.reset(createBackend());
    return m_backend.data();
}

Backend *AccountSession::createBackend(Result *result) const
{
    return BackendLoader::create(m_config.provider, result);
}

void AccountSession::releaseCredentials()
{
    m_credentials.wipe();
}

void AccountSession::onFetched(const Credentials &credentials)
{
    m_credentials = credentials;
    if (m_credentials.userName.isEmpty())
        m_credentials.userName = m_config.params.username;
    emit ready();
}

void AccountSession::onFailed(const Result &result)
{
    qCDebug(lcNetVfsCore) << "Account" << m_config.accountId << "credentials:" << result.toString();
    emit failed(result);
}

} // namespace NetVfs
