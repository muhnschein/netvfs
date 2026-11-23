// SPDX-License-Identifier: LGPL-2.1-or-later
#include "accessmodel.h"
#include "accountstore.h"

#include <Accounts/Account>
#include <Accounts/Manager>

#include <algorithm>

using namespace NetVfs;

namespace NetVfsUi {

QVector<FilesAccount> filesAccounts()
{
    Accounts::Manager manager;
    QVector<FilesAccount> result;
    for (const int id : AccountStore(&manager).filesAccounts()) {
        const Accounts::Account *account = manager.account(static_cast<Accounts::AccountId>(id));
        result.append({ id, account ? account->displayName() : QString() });
    }
    return result;
}

bool isPending(const AppConsent &consent, const QVector<FilesAccount> &accounts)
{
    return !consent.isDecided()
        || std::any_of(accounts.cbegin(), accounts.cend(),
                       [&consent](const FilesAccount &a) { return consent.choice(a.id).isEmpty(); });
}

AccessModel::AccessModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

void AccessModel::setConsumerId(const QString &id)
{
    if (id == m_consumer.id)
        return;
    m_consumer = ConsumerInfo();
    m_consumer.id = id;
    emit consumerIdChanged();
    reload();
}

void AccessModel::setStorePath(const QString &path)
{
    if (path == m_storePath)
        return;
    m_storePath = path;
    emit storePathChanged();
    reload();
}

void AccessModel::setAutoSave(bool autoSave)
{
    if (autoSave == m_autoSave)
        return;
    m_autoSave = autoSave;
    emit autoSaveChanged();
}

void AccessModel::setRequest(bool request)
{
    if (request == m_request)
        return;
    m_request = request;
    emit requestChanged();
    reload();
}

int AccessModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : count();
}

QVariant AccessModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= count())
        return QVariant();
    const FilesAccount &account = m_rows.at(index.row());
    switch (role) {
    case roleId(Role::AccountId):
        return account.id;
    case roleId(Role::Name):
    case Qt::DisplayRole:
        return account.name;
    case roleId(Role::Choice):
        return m_consent.choice(account.id);
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> AccessModel::roleNames() const
{
    QHash<int, QByteArray> names;
    names.insert(roleId(Role::AccountId), "accountId");
    names.insert(roleId(Role::Name), "name");
    names.insert(roleId(Role::Choice), "choice");
    return names;
}

void AccessModel::reload()
{
    beginResetModel();
    const QString id = m_consumer.id;
    if (!ConsentStore::loadConsumer(id, &m_consumer).ok()) {
        m_consumer = ConsumerInfo();
        m_consumer.id = id;
    }
    const ConsentStore store = m_storePath.isEmpty() ? ConsentStore() : ConsentStore(m_storePath);
    m_consent = store.consent(id);
    m_decided = m_consent.isDecided();
    m_rows.clear();
    for (const FilesAccount &account : filesAccounts()) {
        const bool open = m_consent.choice(account.id).isEmpty();
        if (open)
            m_consent.accounts.insert(account.id, QStringLiteral("denied"));
        if (open || !m_request || !m_decided)
            m_rows.append(account);
    }
    if (!m_decided)
        m_consent.newAccounts = QStringLiteral("ask");
    endResetModel();
    emit changed();
}

bool AccessModel::setChoice(int accountId, const QString &choice)
{
    const auto row = std::find_if(m_rows.cbegin(), m_rows.cend(), [accountId](const FilesAccount &a) {
        return a.id == accountId;
    });
    if (row == m_rows.cend() || (choice != QLatin1String("denied") && !isAccessLevel(choice)))
        return false;
    m_consent.accounts.insert(accountId, choice);
    const QModelIndex changed = index(int(row - m_rows.cbegin()));
    emit dataChanged(changed, changed, { roleId(Role::Choice) });
    return !m_autoSave || save();
}

bool AccessModel::setNewAccounts(const QString &choice)
{
    if (choice != QLatin1String("ask") && choice != QLatin1String("denied") && !isAccessLevel(choice))
        return false;
    m_consent.newAccounts = choice;
    emit changed();
    return !m_autoSave || save();
}

bool AccessModel::save()
{
    const ConsentStore store = m_storePath.isEmpty() ? ConsentStore() : ConsentStore(m_storePath);
    AppConsent stored = store.consent(m_consumer.id);
    for (const FilesAccount &account : m_rows)
        stored.accounts.insert(account.id, m_consent.accounts.value(account.id));
    stored.newAccounts = m_consent.newAccounts;
    if (!store.setConsent(m_consumer.id, stored) || store.consent(m_consumer.id) != stored)
        return false;
    if (!m_decided) {
        m_decided = true;
        emit changed();
    }
    return true;
}

}
