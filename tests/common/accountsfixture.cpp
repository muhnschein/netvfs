// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accountsfixture.h"

#include <Accounts/Account>
#include <Accounts/Manager>
#include <Accounts/Service>

#include <QtCore/QDir>
#include <QtCore/QFile>

namespace NetVfs {
namespace Test {

namespace {
void writeFile(const QString &path, const QByteArray &content)
{
    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate))
        file.write(content);
}
} // namespace

AccountsFixture::AccountsFixture(const QStringList &providers)
{
    QDir(m_dir.path()).mkpath(QStringLiteral("providers"));
    QDir(m_dir.path()).mkpath(QStringLiteral("services"));
    qputenv("ACCOUNTS", m_dir.path().toLocal8Bit());
    qputenv("AG_PROVIDERS", (m_dir.path() + QStringLiteral("/providers")).toLocal8Bit());
    qputenv("AG_SERVICES", (m_dir.path() + QStringLiteral("/services")).toLocal8Bit());
    for (const QString &provider : providers)
        installProvider(provider);
}

AccountsFixture::~AccountsFixture()
{
    delete m_manager;
}

Accounts::Manager *AccountsFixture::manager()
{
    if (!m_manager)
        m_manager = new Accounts::Manager;
    return m_manager;
}

void AccountsFixture::installProvider(const QString &provider)
{
    const QByteArray p = provider.toUtf8();
    writeFile(m_dir.path() + QStringLiteral("/providers/") + provider + QStringLiteral(".provider"),
              "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<provider version=\"1.0\" id=\"" + p
              + "\">\n  <name>" + p.toUpper() + "</name>\n</provider>\n");
    writeFile(m_dir.path() + QStringLiteral("/services/") + provider + QStringLiteral("-backup.service"),
              "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<service id=\"" + p + "-backup\">\n"
              "  <type>storage</type>\n  <name>Backups</name>\n  <provider>" + p + "</provider>\n"
              "</service>\n");
}

int AccountsFixture::createAccount(const QString &provider, const QVariantMap &globals,
                                   const QString &backupsPath, quint32 credentialsId)
{
    Accounts::Account *account = manager()->createAccount(provider);
    if (!account)
        return 0;
    account->setDisplayName(globals.value(QStringLiteral("netvfs/username")).toString()
                            + QLatin1Char('@') + globals.value(QStringLiteral("netvfs/host")).toString());
    account->selectService(Accounts::Service());
    for (auto it = globals.constBegin(); it != globals.constEnd(); ++it)
        account->setValue(it.key(), it.value());
    if (credentialsId)
        account->setCredentialsId(credentialsId);
    account->setEnabled(true);
    const Accounts::Service service = manager()->service(provider + QStringLiteral("-backup"));
    if (service.isValid()) {
        account->selectService(service);
        account->setEnabled(true);
        if (!backupsPath.isEmpty())
            account->setValue(QStringLiteral("backups_path"), backupsPath);
        account->selectService(Accounts::Service());
    }
    if (!account->syncAndBlock())
        return 0;
    return static_cast<int>(account->id());
}

QVariant AccountsFixture::value(int accountId, const QString &key, const QString &service)
{
    // A fresh manager so values written through other managers are seen.
    Accounts::Manager fresh;
    Accounts::Account *account = fresh.account(static_cast<Accounts::AccountId>(accountId));
    if (!account)
        return QVariant();
    account->selectService(service.isEmpty() ? Accounts::Service() : fresh.service(service));
    return account->value(key);
}

} // namespace Test
} // namespace NetVfs
