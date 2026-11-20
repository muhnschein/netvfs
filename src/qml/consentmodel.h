// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_CONSENTMODEL_H
#define NETVFS_QML_CONSENTMODEL_H

#include "consentstore.h"

#include <QtCore/QAbstractListModel>

namespace NetVfsUi {

// Registered consumers of netvfs-bridge (NetVfsConsentPage): name, icon, and whether one waits for
// the user (not decided, or a files account without a choice while new accounts ask).
class ConsentModel : public QAbstractListModel
{
    Q_OBJECT
    Q_DISABLE_COPY(ConsentModel)
    // Consent file; empty: ConsentStore::defaultFilePath(). Set by tests.
    Q_PROPERTY(QString storePath READ storePath WRITE setStorePath NOTIFY storePathChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum class Role { ConsumerId = Qt::UserRole + 1, DisplayName, Icon, Pending };
    static constexpr int roleId(Role role) { return static_cast<int>(role); }

    explicit ConsentModel(QObject *parent = nullptr);

    QString storePath() const { return m_storePath; }
    void setStorePath(const QString &path);
    int count() const { return int(m_consumers.size()); }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void reload();
    // The first app waiting for the user; "" when none.
    Q_INVOKABLE QString firstPending() const;

    // Launcher icon of `executable` from the hicolor theme; "" when none.
    static QString iconOf(const QString &executable, const QString &iconsDir = QString());

Q_SIGNALS:
    void storePathChanged();
    void countChanged();

private:
    QString m_storePath;
    QVector<NetVfs::ConsumerInfo> m_consumers;
    QVector<bool> m_pending;
};

}
#endif
