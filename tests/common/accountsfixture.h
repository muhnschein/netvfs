// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_ACCOUNTSFIXTURE_H
#define NETVFS_TEST_ACCOUNTSFIXTURE_H

#include <QtCore/QTemporaryDir>
#include <QtCore/QVariantMap>

namespace Accounts {
class Manager;
}

namespace NetVfs {
namespace Test {

// A private accounts database (ACCOUNTS, AG_PROVIDERS, AG_SERVICES point into a
// temporary directory). Create it before the first Accounts::Manager in the
// process. Providers get a "<provider>-backup" storage service and a
// "<provider>-files" netvfs-files service (SPEC-v2 XA-1).
class Q_DECL_EXPORT AccountsFixture
{
public:
    explicit AccountsFixture(const QStringList &providers = QStringList());
    ~AccountsFixture();

    bool isValid() const { return m_dir.isValid(); }
    QString path() const { return m_dir.path(); }
    Accounts::Manager *manager();

    void installProvider(const QString &provider);

    // Creates an enabled account with the backup service enabled.
    // `globals` are written to the global service; `backupsPath`, when not
    // empty, to the backup service. Returns the account id (0 on failure).
    int createAccount(const QString &provider, const QVariantMap &globals,
                      const QString &backupsPath = QString(), quint32 credentialsId = 0);

    QVariant value(int accountId, const QString &key, const QString &service = QString());

    // Enables or disables `service` ("" for the account itself) and writes
    // `values` to it. Returns false on failure.
    bool setService(int accountId, const QString &service, bool enabled, const QVariantMap &values = QVariantMap());

private:
    QTemporaryDir m_dir;
    Accounts::Manager *m_manager = nullptr;
};

} // namespace Test
} // namespace NetVfs

#endif
