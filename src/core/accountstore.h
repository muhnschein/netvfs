// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ACCOUNTSTORE_H
#define NETVFS_ACCOUNTSTORE_H

#include "error.h"
#include "servicepolicy.h"
#include "types.h"

#include <QtCore/QList>

namespace Accounts {
class Manager;
}

namespace NetVfs {

// Provider keys: "netvfs/<provider>/<key>".
namespace Keys {
NETVFS_EXPORT extern const char Host[];
NETVFS_EXPORT extern const char Port[];
NETVFS_EXPORT extern const char Username[];
NETVFS_EXPORT extern const char Attention[];
NETVFS_EXPORT extern const char BackupsPath[];
NETVFS_EXPORT extern const char FilesRoot[];
NETVFS_EXPORT extern const char DefaultCredentialsUsername[];
NETVFS_EXPORT extern const char CredentialsNeedUpdate[];
NETVFS_EXPORT extern const char CredentialsNeedUpdateFrom[];
NETVFS_EXPORT extern const char HostKeySeen[];
NETVFS_EXPORT QString providerKey(const QString &provider, const QString &key);
}

NETVFS_EXPORT extern const char DefaultBackupsPath[];
NETVFS_EXPORT extern const char CredentialsApplication[];
NETVFS_EXPORT extern const char CredentialsName[];
NETVFS_EXPORT extern const char FilesServiceType[];
enum class Attention {
    None,
    AuthFailed,
    ServerIdentityChanged
};

NETVFS_EXPORT QString attentionToString(Attention attention);
NETVFS_EXPORT Attention attentionFromString(const QString &value);
NETVFS_EXPORT Attention attentionForError(Error error);
NETVFS_EXPORT QString backupServiceName(const QString &provider);
NETVFS_EXPORT QString filesServiceName(const QString &provider);

struct AccountConfig {
    int accountId = 0;
    QString provider;
    QString displayName;
    bool enabled = false;
    Service service = Service::Backup;
    bool serviceEnabled = false;
    ConnectionParams params;
    QString backupsPath;
    QString filesRoot;
    QString securityProfile;
    bool insecureAllowed = false;
    quint32 credentialsId = 0;
    Attention attention = Attention::None;
    bool credentialsNeedUpdate = false;
};

class NETVFS_EXPORT AccountStore
{
public:
    explicit AccountStore(Accounts::Manager *manager);

    // Policy not applied here, see AccountSession and checkServicePolicy().
    Result load(int accountId, Service service, AccountConfig *out) const;

    // Enabled accounts whose "<provider>-files" service is enabled, ascending id.
    QList<int> filesAccounts() const;

    // `seenIdentityPin` recorded as host_key_seen when given. Files and backup runs record
    // attention alike: services share server identity and credentials, so a failure pauses both
    // until the update flow clears it.
    Result setAttention(int accountId, Service service, Attention attention,
                        const QString &seenIdentityPin = QString()) const;
    // Clears netvfs/attention, CredentialsNeedUpdate(From) and host_key_seen.
    Result clearAttention(int accountId) const;

private:
    Accounts::Manager *m_manager;
};

}
#endif
