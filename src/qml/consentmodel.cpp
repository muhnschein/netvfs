// SPDX-License-Identifier: LGPL-2.1-or-later
#include "consentmodel.h"
#include "accessmodel.h"

#include <QtCore/QFile>
#include <QtCore/QFileInfo>

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
    case roleId(Role::Icon):
        return iconOf(consumer.executable);
    case roleId(Role::Pending):
        return m_pending.at(index.row());
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> ConsentModel::roleNames() const
{
    QHash<int, QByteArray> names;
    names.insert(roleId(Role::ConsumerId), "consumerId");
    names.insert(roleId(Role::DisplayName), "displayName");
    names.insert(roleId(Role::Icon), "icon");
    names.insert(roleId(Role::Pending), "pending");
    return names;
}

void ConsentModel::reload()
{
    const int before = count();
    beginResetModel();
    m_consumers = ConsentStore::consumers();
    const ConsentStore store = m_storePath.isEmpty() ? ConsentStore() : ConsentStore(m_storePath);
    const QVector<FilesAccount> accounts = filesAccounts();
    m_pending.clear();
    for (const ConsumerInfo &consumer : m_consumers)
        m_pending << isPending(store.consent(consumer.id), accounts);
    endResetModel();
    if (count() != before)
        emit countChanged();
}

QString ConsentModel::firstPending() const
{
    const auto row = int(m_pending.indexOf(true));
    return row < 0 ? QString() : m_consumers.at(row).id;
}

QString ConsentModel::iconOf(const QString &executable, const QString &iconsDir)
{
    const QString dir = iconsDir.isEmpty() ? QStringLiteral("/usr/share/icons/hicolor") : iconsDir;
    const QString name = QFileInfo(executable).fileName();
    for (const char *size : { "172x172", "128x128", "108x108", "86x86" }) {
        const QString path = QStringLiteral("%1/%2/apps/%3.png").arg(dir, QLatin1String(size), name);
        if (!name.isEmpty() && QFile::exists(path))
            return path;
    }
    return QString();
}

}
