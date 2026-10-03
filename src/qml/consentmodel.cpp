// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentmodel.h"

using namespace NetVfs;

namespace NetVfsUi {

ConsentModel::ConsentModel(QObject *parent)
    : QAbstractListModel(parent)
{
    reload();
}

void ConsentModel::setStorePath(const QString &path)
{
    if (path == m_storePath)
        return;
    m_storePath = path;
    emit storePathChanged();
    reload();
}

int ConsentModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : count();
}

QVariant ConsentModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= count())
        return QVariant();
    const ConsumerInfo &consumer = m_consumers.at(index.row());
    switch (role) {
    case roleId(Role::ConsumerId):
        return consumer.id;
    case roleId(Role::DisplayName):
    case Qt::DisplayRole:
        return consumer.displayName;
    case roleId(Role::Consent):
        return consentToString(m_consents.at(index.row()));
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> ConsentModel::roleNames() const
{
    QHash<int, QByteArray> names;
    names.insert(roleId(Role::ConsumerId), "consumerId");
    names.insert(roleId(Role::DisplayName), "displayName");
    names.insert(roleId(Role::Consent), "consent");
    return names;
}

void ConsentModel::reload()
{
    const int before = count();
    beginResetModel();
    m_consumers = ConsentStore::consumers();
    const ConsentStore consents = consentStore();
    m_consents.clear();
    for (const ConsumerInfo &consumer : m_consumers)
        m_consents << consents.consent(consumer.id);
    endResetModel();
    if (count() != before)
        emit countChanged();
}

bool ConsentModel::grant(const QString &consumerId)
{
    return store(consumerId, Consent::Granted);
}

bool ConsentModel::revoke(const QString &consumerId)
{
    return store(consumerId, Consent::Denied);
}

QString ConsentModel::consent(const QString &consumerId) const
{
    return consentToString(consentStore().consent(consumerId));
}

bool ConsentModel::store(const QString &consumerId, Consent consent)
{
    for (int row = 0; row < count(); ++row) {
        if (m_consumers.at(row).id != consumerId)
            continue;
        ConsentStore consents = consentStore();
        consents.setConsent(consumerId, consent);
        if (consents.consent(consumerId) != consent)   // not writable
            return false;
        m_consents[row] = consent;
        const QModelIndex changed = index(row);
        emit dataChanged(changed, changed, { roleId(Role::Consent) });
        return true;
    }
    return false;   // only registered consumers
}

ConsentStore ConsentModel::consentStore() const
{
    return m_storePath.isEmpty() ? ConsentStore() : ConsentStore(m_storePath);
}

} // namespace NetVfsUi
