// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_ACCOUNTSTORE_H
#define NETVFS_ACCOUNTSTORE_H

#include "error.h"
#include "types.h"

namespace Accounts {
class Manager;
}

namespace NetVfs {

// Settings keys (SPEC 6.2). Provider keys are "netvfs/<provider>/<key>".
namespace Keys {
NETVFS_EXPORT extern const char Host[];
NETVFS_EXPORT extern const char Port[];
NETVFS_EXPORT extern const char Username[];
NETVFS_EXPORT extern const char Attention[];
NETVFS_EXPORT extern const char BackupsPath[];
NETVFS_EXPORT extern const char DefaultCredentialsUsername[];
NETVFS_EXPORT extern const char CredentialsNeedUpdate[];
NETVFS_EXPORT extern const char CredentialsNeedUpdateFrom[];
NETVFS_EXPORT extern const char HostKeySeen[];          // option key, sftp
NETVFS_EXPORT QString providerKey(const QString &provider, const QString &key);
} // namespace Keys

NETVFS_EXPORT extern const char DefaultBackupsPath[];   // "Sailfish OS/Backups"
NETVFS_EXPORT extern const char CredentialsApplication[]; // "netvfs"
NETVFS_EXPORT extern const char CredentialsName[];        // "default"

enum class Attention {
    None,
    AuthFailed,              // "auth-failed"
    ServerIdentityChanged    // "server-identity-changed"
};

NETVFS_EXPORT QString attentionToString(Attention attention);
NETVFS_EXPORT Attention attentionFromString(const QString &value);
// SPEC 8.7: which attention state a failed run records.
NETVFS_EXPORT Attention attentionForError(Error error);
NETVFS_EXPORT QString backupServiceName(const QString &provider);

struct AccountConfig {
    int accountId = 0;
    QString provider;
    QString displayName;
    bool enabled = false;
    ConnectionParams params;
    QString backupsPath;
    quint32 credentialsId = 0;
    Attention attention = Attention::None;
    bool credentialsNeedUpdate = false;
};

// Reads and updates netvfs accounts in the accounts database (SPEC C-1, C-6).
class NETVFS_EXPORT AccountStore
{
public:
    explicit AccountStore(Accounts::Manager *manager);

    Result load(int accountId, AccountConfig *out) const;

    // SPEC 6.4. `seenIdentityPin` is recorded as host_key_seen when given.
    Result setAttention(int accountId, Attention attention, const QString &seenIdentityPin = QString()) const;
    // Clears netvfs/attention, CredentialsNeedUpdate(From) and host_key_seen.
    Result clearAttention(int accountId) const;

private:
    Accounts::Manager *m_manager;
};

} // namespace NetVfs

#endif
