// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_LOCATION_H
#define NETVFS_BRIDGE_LOCATION_H

#include "accountstore.h"
#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QVariantMap>
#include <QtCore/QVector>

#include <functional>
#include <memory>

// SPEC-v2 XB-7: what a consumer may see. Locations are netvfs accounts whose
// Files service is enabled, and ad-hoc locations this consumer created.
namespace NetVfs {
namespace Bridge {

enum class LocationKind { Account, AdHoc };

struct LocationSpec {
    QString id;                       // "account:<n>" or "adhoc:<n>"
    LocationKind kind = LocationKind::Account;
    int accountId = 0;
    QString provider;
    QString name;                     // display name
    ConnectionParams params;          // never holds a secret
    QString startPath;                // files_root / URL path, normalised
    Attention attention = Attention::None;
    // Ad-hoc only: the secret the consumer gave (XB-16), held for the
    // connections of the pool and wiped when the location goes away.
    std::shared_ptr<Credentials> adHocCredentials;

    QString hostKey() const;          // "<provider>://<host>:<port>", per-host limits (XB-12)
    QVariantMap info() const;         // ListLocations a{sv}
};

// A netvfs account with the Files service enabled.
struct AccountLocation {
    int accountId = 0;
    QString provider;
    QString displayName;
    ConnectionParams params;
    QString filesRoot;
    Attention attention = Attention::None;
};

// Access to the accounts database, behind an interface so that tests run
// without libaccounts and so that the AccountSession signature change of the
// accounts work (XA-4, AccountSession::open(id, Service::Files, parent)) stays
// a one-line change in accountdirectory.cpp.
class AccountDirectory : public QObject
{
    Q_OBJECT
public:
    using Fetched = std::function<void(const Result &result, const ConnectionParams &params,
                                       const Credentials &credentials)>;

    using QObject::QObject;
    ~AccountDirectory() override;

    virtual QVector<AccountLocation> filesAccounts() = 0;
    // Asynchronous (signond). `done` runs on the main thread exactly once.
    virtual void fetch(int accountId, const Fetched &done) = 0;
    // SPEC 6.4 / XB-14: as Buteo does after a failed run.
    virtual void setAttention(int accountId, Attention attention, const QString &seenPin) = 0;

Q_SIGNALS:
    void changed();
};

// libaccounts-qt5 + signond implementation.
class LibAccountsDirectory : public AccountDirectory
{
    Q_OBJECT
public:
    explicit LibAccountsDirectory(QObject *parent = nullptr);
    ~LibAccountsDirectory() override;

    QVector<AccountLocation> filesAccounts() override;
    void fetch(int accountId, const Fetched &done) override;
    void setAttention(int accountId, Attention attention, const QString &seenPin) override;

    // XA-1: service type of the "<provider>-files" services.
    static const char FilesServiceType[];

private:
    class Private;
    std::unique_ptr<Private> d;
};

} // namespace Bridge
} // namespace NetVfs

#endif
