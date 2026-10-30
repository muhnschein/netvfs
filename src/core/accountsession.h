// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ACCOUNTSESSION_H
#define NETVFS_ACCOUNTSESSION_H

#include "accountstore.h"
#include "backend.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>

namespace Accounts {
class Manager;
}

namespace NetVfs {

class SecretSource;

// open() loads the account for one service, fetches the secret async; exactly one of ready() or
// failed() follows.
// Config not allowed for the service (checkServicePolicy()) fails with SecurityPolicy before any
// secret is read.
class NETVFS_EXPORT AccountSession : public QObject
{
    Q_OBJECT
public:
    static AccountSession *open(int accountId, Service service, QObject *parent);

    // Takes ownership of `secrets`; `manager` must outlive the session.
    AccountSession(Accounts::Manager *manager, SecretSource *secrets, QObject *parent = nullptr);
    ~AccountSession() override;

    void start(int accountId, Service service);

    const AccountConfig &config() const { return m_config; }
    ConnectionParams params() const { return m_config.params; }
    const Credentials &credentials() const { return m_credentials; }
    QString backupsPath() const { return m_config.backupsPath; }
    QString filesRoot() const { return m_config.filesRoot; }
    Service service() const { return m_config.service; }

    // Owned by the session; created on first use. Thread-confined to the first calling thread.
    Backend *backend();
    Backend *createBackend(Result *result = nullptr) const;

    void releaseCredentials();

Q_SIGNALS:
    void ready();
    void failed(const NetVfs::Result &result);

private:
    void onFetched(const NetVfs::Credentials &credentials);
    void onFailed(const NetVfs::Result &result);

    Accounts::Manager *m_manager;
    SecretSource *m_secrets;
    AccountConfig m_config;
    Credentials m_credentials;
    QScopedPointer<Backend> m_backend;
};

}
#endif
