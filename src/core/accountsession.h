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

// Convenience: account parameters + credentials + backend + policy (SPEC 5.2,
// SPEC-v2 XA-4). open() loads the account for one service synchronously and
// fetches the secret asynchronously; exactly one of ready() or failed()
// follows.
//
// A configuration that is not allowed for the service (checkServicePolicy(),
// e.g. an SMB guest profile or allow_insecure for Backup) fails with
// SecurityPolicy before any secret is read. params() are those of the
// service (paramsForService()). Whether the service is enabled is reported
// in config().serviceEnabled; consumers list accounts with
// AccountStore::filesAccounts() (Files) or through the platform (Backup).
class NETVFS_EXPORT AccountSession : public QObject
{
    Q_OBJECT
public:
    // Production entry point: default accounts manager and signond.
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

    // Owned by the session; created on first use. Thread-confined to the
    // thread that first calls a Backend method.
    Backend *backend();
    // A fresh, caller-owned backend for the account's provider.
    Backend *createBackend(Result *result = nullptr) const;

    // Wipes the held secret (SEC-5).
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

} // namespace NetVfs

#endif
