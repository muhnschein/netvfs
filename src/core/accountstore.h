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

// Settings keys (SPEC 6.2). Provider keys are "netvfs/<provider>/<key>"
// (option names in servicepolicy.h, OptionKeys).
namespace Keys {
NETVFS_EXPORT extern const char Host[];
NETVFS_EXPORT extern const char Port[];
NETVFS_EXPORT extern const char Username[];
NETVFS_EXPORT extern const char Attention[];
NETVFS_EXPORT extern const char BackupsPath[];         // service <p>-backup
NETVFS_EXPORT extern const char FilesRoot[];           // service <p>-files (SPEC-v2-review 2.17)
NETVFS_EXPORT extern const char DefaultCredentialsUsername[];
NETVFS_EXPORT extern const char CredentialsNeedUpdate[];
NETVFS_EXPORT extern const char CredentialsNeedUpdateFrom[];
NETVFS_EXPORT extern const char HostKeySeen[];          // option key, sftp
NETVFS_EXPORT QString providerKey(const QString &provider, const QString &key);
} // namespace Keys

NETVFS_EXPORT extern const char DefaultBackupsPath[];   // "Sailfish OS/Backups"
NETVFS_EXPORT extern const char CredentialsApplication[]; // "netvfs"
NETVFS_EXPORT extern const char CredentialsName[];        // "default"
NETVFS_EXPORT extern const char FilesServiceType[];       // "netvfs-files" (SPEC-v2 XA-1)

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
NETVFS_EXPORT QString filesServiceName(const QString &provider);

struct AccountConfig {
    int accountId = 0;
    QString provider;
    QString displayName;
    bool enabled = false;          // the account (global)
    Service service = Service::Backup;   // the service it was loaded for (XA-4)
    bool serviceEnabled = false;   // account and `service` both enabled
    ConnectionParams params;
    QString backupsPath;           // never empty (default DefaultBackupsPath)
    QString filesRoot;             // start folder for browsing; "" = the backend's base folder
    QString securityProfile;       // SMB profile in effect (XM-1); "" for other providers
    bool insecureAllowed = false;  // allow_insecure (XA-3)
    quint32 credentialsId = 0;
    Attention attention = Attention::None;
    bool credentialsNeedUpdate = false;
};

// Reads and updates netvfs accounts in the accounts database (SPEC C-1, C-6).
class NETVFS_EXPORT AccountStore
{
public:
    explicit AccountStore(Accounts::Manager *manager);

    // Loads the account for `service`. Policy (XA-4) is not applied here,
    // see AccountSession and checkServicePolicy().
    Result load(int accountId, Service service, AccountConfig *out) const;

    // SPEC-v2 XA-1: enabled accounts whose "<provider>-files" service is
    // enabled, in ascending id order. What file-browsing consumers list.
    QList<int> filesAccounts() const;

    // SPEC 6.4. `seenIdentityPin` is recorded as host_key_seen when given.
    // SPEC-v2 XA-8, XB-14: a Files run records attention exactly like a
    // backup run (same keys, same values): both services share the server
    // identity and the credentials, so a refused identity or secret is a
    // property of the account. It therefore also pauses backups until the
    // update flow clears it. Only CredentialsNeedUpdateFrom names the
    // service that noticed it (SPEC-v2-review 2.18).
    Result setAttention(int accountId, Service service, Attention attention,
                        const QString &seenIdentityPin = QString()) const;
    // Clears netvfs/attention, CredentialsNeedUpdate(From) and host_key_seen.
    Result clearAttention(int accountId) const;

private:
    Accounts::Manager *m_manager;
};

} // namespace NetVfs

#endif
