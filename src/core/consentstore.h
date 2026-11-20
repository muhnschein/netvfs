// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_CONSENTSTORE_H
#define NETVFS_CONSENTSTORE_H

#include "error.h"

#include <QtCore/QMap>
#include <QtCore/QString>
#include <QtCore/QVector>

namespace NetVfs {

// Consumer of netvfs-bridge, registered by /usr/share/netvfs/consumers/<id>.conf
// (NETVFS_CONSUMERS_DIR overrides):
// [Consumer]
// Id=lautta
// DisplayName=Lautta
// Executable=/usr/bin/harbour-lautta
// DataDir=.local/share/org.netvfs/lautta
// Access=full
struct NETVFS_EXPORT ConsumerInfo {
    QString id;
    QString displayName;
    QString executable;
    QString dataDir;
    // Level the app asks for; missing or not a level: "read".
    QString access = QStringLiteral("read");
    static bool isValidId(const QString &id);
    static bool isValidDataDir(const QString &dataDir);
    static bool isValidExecutable(const QString &executable);
};

// Levels: "full", "read-add", "read", "add".
NETVFS_EXPORT bool isAccessLevel(const QString &word);

// What the user decided for one app in ~/.config/netvfs/bridge.conf, as the bridge reads it:
// [Consent] <id>=ask|<level>|denied once decided (for accounts without their own choice),
// [Access] <id>\<accountId>=<level>|denied per account.
struct NETVFS_EXPORT AppConsent {
    // "": not decided; "ask", "denied" or a level.
    QString newAccounts;
    // Account id: "denied" or a level.
    QMap<int, QString> accounts;

    bool isDecided() const { return !newAccounts.isEmpty(); }
    // Account `accountId`'s choice ("denied" or a level); "": waits for the user.
    QString choice(int accountId) const;
    friend bool operator==(const AppConsent &a, const AppConsent &b)
    {
        return a.newAccounts == b.newAccounts && a.accounts == b.accounts;
    }
    friend bool operator!=(const AppConsent &a, const AppConsent &b) { return !(a == b); }
};

class NETVFS_EXPORT ConsentStore
{
public:
    ConsentStore();
    explicit ConsentStore(const QString &filePath);

    static QString defaultFilePath();
    QString filePath() const { return m_path; }

    // Reads the file on every call.
    AppConsent consent(const QString &id) const;
    // Replaces what is stored for `id`; false when it could not be stored.
    bool setConsent(const QString &id, const AppConsent &consent) const;

    static QString consumersDir();
    static QVector<ConsumerInfo> consumers();
    static Result loadConsumer(const QString &id, ConsumerInfo *out);
    static Result parseConsumerFile(const QString &path, ConsumerInfo *out);

private:
    QString m_path;
};

}
#endif
