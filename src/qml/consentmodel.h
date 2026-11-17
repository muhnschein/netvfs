// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_CONSENTMODEL_H
#define NETVFS_QML_CONSENTMODEL_H

#include "consentstore.h"

#include <QtCore/QAbstractListModel>

namespace NetVfsUi {

// Registered consumers of netvfs-bridge and the user's consent for each (NetVfsConsentPage).
// grant()/revoke() write bridge.conf at once (ConsentStore); a running bridge watches it and closes
// a revoked app's connections immediately.
class ConsentModel : public QAbstractListModel
{
    Q_OBJECT
    Q_DISABLE_COPY(ConsentModel)
    // Consent file; empty: ConsentStore::defaultFilePath(). Set by tests.
    Q_PROPERTY(QString storePath READ storePath WRITE setStorePath NOTIFY storePathChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum class Role { ConsumerId = Qt::UserRole + 1, DisplayName, Consent };
    static constexpr int roleId(Role role) { return static_cast<int>(role); }

    explicit ConsentModel(QObject *parent = nullptr);

    QString storePath() const { return m_storePath; }
    void setStorePath(const QString &path);
    int count() const { return int(m_consumers.size()); }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void reload();
    // Return false when the consent could not be stored.
    Q_INVOKABLE bool grant(const QString &consumerId);
    Q_INVOKABLE bool revoke(const QString &consumerId);
    // "unknown", "granted" or "denied".
    Q_INVOKABLE QString consent(const QString &consumerId) const;

Q_SIGNALS:
    void storePathChanged();
    void countChanged();

private:
    bool store(const QString &consumerId, NetVfs::Consent consent);
    NetVfs::ConsentStore consentStore() const;

    QString m_storePath;
    QVector<NetVfs::ConsumerInfo> m_consumers;
    QVector<NetVfs::Consent> m_consents;
};

}
#endif
