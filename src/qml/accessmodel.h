// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_ACCESSMODEL_H
#define NETVFS_QML_ACCESSMODEL_H

#include "consentstore.h"

#include <QtCore/QAbstractListModel>

namespace NetVfsUi {

struct FilesAccount {
    int id = 0;
    QString name;
};

QVector<FilesAccount> filesAccounts();

bool isPending(const NetVfs::AppConsent &consent, const QVector<FilesAccount> &accounts);

class AccessModel : public QAbstractListModel
{
    Q_OBJECT
    Q_DISABLE_COPY(AccessModel)
    Q_PROPERTY(QString consumerId READ consumerId WRITE setConsumerId NOTIFY consumerIdChanged)
    Q_PROPERTY(QString storePath READ storePath WRITE setStorePath NOTIFY storePathChanged)
    Q_PROPERTY(bool autoSave READ autoSave WRITE setAutoSave NOTIFY autoSaveChanged)
    Q_PROPERTY(bool request READ request WRITE setRequest NOTIFY requestChanged)
    Q_PROPERTY(int count READ count NOTIFY changed)
    Q_PROPERTY(QString displayName READ displayName NOTIFY changed)
    Q_PROPERTY(QString asked READ asked NOTIFY changed)
    Q_PROPERTY(bool decided READ decided NOTIFY changed)
    Q_PROPERTY(QString newAccounts READ newAccounts NOTIFY changed)

public:
    enum class Role { AccountId = Qt::UserRole + 1, Name, Choice };
    static constexpr int roleId(Role role) { return static_cast<int>(role); }

    explicit AccessModel(QObject *parent = nullptr);

    QString consumerId() const { return m_consumer.id; }
    void setConsumerId(const QString &id);
    QString storePath() const { return m_storePath; }
    void setStorePath(const QString &path);
    bool autoSave() const { return m_autoSave; }
    void setAutoSave(bool autoSave);
    bool request() const { return m_request; }
    void setRequest(bool request);
    int count() const { return int(m_rows.size()); }
    QString displayName() const { return m_consumer.displayName; }
    QString asked() const { return m_consumer.access; }
    bool decided() const { return m_decided; }
    QString newAccounts() const { return m_consent.newAccounts; }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void reload();
    Q_INVOKABLE bool setChoice(int accountId, const QString &choice);
    Q_INVOKABLE bool setNewAccounts(const QString &choice);
    Q_INVOKABLE bool save();

Q_SIGNALS:
    void consumerIdChanged();
    void storePathChanged();
    void autoSaveChanged();
    void requestChanged();
    void changed();

private:
    QString m_storePath;
    bool m_autoSave = true;
    bool m_request = false;
    bool m_decided = false;
    NetVfs::ConsumerInfo m_consumer;
    NetVfs::AppConsent m_consent;
    QVector<FilesAccount> m_rows;
};

}
#endif
