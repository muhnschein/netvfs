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

// Enabled accounts with file browsing on, ascending id: what the bridge lists.
QVector<FilesAccount> filesAccounts();

// Whether `consent` waits for the user: not decided, or an account of `accounts` without a choice.
bool isPending(const NetVfs::AppConsent &consent, const QVector<FilesAccount> &accounts);

// What one app may do per account (NetVfsAccessPage, NetVfsAccessRequestDialog). Rows: the files
// accounts; in `request` mode once decided, only those without a choice. An account without a choice
// shows "denied". Changes write bridge.conf at once with `autoSave`, else on save(); a running bridge
// watches the file and applies them.
class AccessModel : public QAbstractListModel
{
    Q_OBJECT
    Q_DISABLE_COPY(AccessModel)
    Q_PROPERTY(QString consumerId READ consumerId WRITE setConsumerId NOTIFY consumerIdChanged)
    // Consent file; empty: ConsentStore::defaultFilePath(). Set by tests.
    Q_PROPERTY(QString storePath READ storePath WRITE setStorePath NOTIFY storePathChanged)
    Q_PROPERTY(bool autoSave READ autoSave WRITE setAutoSave NOTIFY autoSaveChanged)
    Q_PROPERTY(bool request READ request WRITE setRequest NOTIFY requestChanged)
    Q_PROPERTY(int count READ count NOTIFY changed)
    Q_PROPERTY(QString displayName READ displayName NOTIFY changed)
    // Level the app asks for.
    Q_PROPERTY(QString asked READ asked NOTIFY changed)
    // Decided before: a request is about new accounts.
    Q_PROPERTY(bool decided READ decided NOTIFY changed)
    // "ask", "denied" or a level.
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
    // `choice`: "denied" or a level. False for an unknown account or word, or a failed save.
    Q_INVOKABLE bool setChoice(int accountId, const QString &choice);
    // `choice`: "ask", "denied" or a level.
    Q_INVOKABLE bool setNewAccounts(const QString &choice);
    // Stores the choices shown; false when they could not be stored.
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
