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
class Q_DECL_EXPORT AccountsFixture
{
public:
    explicit AccountsFixture(const QStringList &providers = QStringList());
    ~AccountsFixture();

    bool isValid() const { return m_dir.isValid(); }
    QString path() const { return m_dir.path(); }
    Accounts::Manager *manager();

    void installProvider(const QString &provider);

    int createAccount(const QString &provider, const QVariantMap &globals,
                      const QString &backupsPath = QString(), quint32 credentialsId = 0);

    QVariant value(int accountId, const QString &key, const QString &service = QString());

    bool setService(int accountId, const QString &service, bool enabled, const QVariantMap &values = QVariantMap());

private:
    QTemporaryDir m_dir;
    Accounts::Manager *m_manager = nullptr;
};

}
}

#endif
