// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SERVICEPOLICY_H
#define NETVFS_SERVICEPOLICY_H

#include "error.h"
#include "types.h"

namespace NetVfs {

// Backup = "<provider>-backup" (type "storage", Buteo). Files = "<provider>-files" (type
// "netvfs-files", bridge and other consumers).
enum class Service { Backup, Files };

NETVFS_EXPORT QString serviceName(const QString &provider, Service service);
NETVFS_EXPORT QString serviceId(Service service);
NETVFS_EXPORT bool serviceFromId(const QString &id, Service *service);

// Option keys of ConnectionParams::options, stored as "netvfs/<provider>/<key>".
namespace OptionKeys {
NETVFS_EXPORT extern const char HostKey[];
NETVFS_EXPORT extern const char AuthMode[];
NETVFS_EXPORT extern const char SecurityProfile[];
NETVFS_EXPORT extern const char Share[];
NETVFS_EXPORT extern const char Shares[];
NETVFS_EXPORT extern const char ShowAdminShares[];
NETVFS_EXPORT extern const char AllowInsecure[];
}
namespace SecurityProfiles {
NETVFS_EXPORT extern const char Strict[];
NETVFS_EXPORT extern const char Signed[];
NETVFS_EXPORT extern const char Guest[];
}

// SMB profile in effect: security_profile, else "strict". Empty for other providers. Returned as
// stored (unknown refused by checkServicePolicy()).
NETVFS_EXPORT QString securityProfile(const ConnectionParams &params);

// Unprotected or weakened transport needs account consent (allow_insecure=true): SMB profile guest.
NETVFS_EXPORT bool isInsecureConfiguration(const ConnectionParams &params);

// Allowed per service:
// smb strict, signed: backup yes, files yes
// smb guest: backup no, files with allow_insecure
// smb unknown profile: no, no
// smb without share (server mode): backup no, files yes
// allow_insecure=true (any provider): backup no, files yes
// auth_mode=interactive: backup no, files yes
// anything else: yes, yes
// Refused = SecurityPolicy with a message naming the reason.
NETVFS_EXPORT Result checkServicePolicy(const ConnectionParams &params, Service service);

// Accounts that legitimately have no stored secret: auth_mode=interactive and smb guest.
NETVFS_EXPORT bool secretOptional(const ConnectionParams &params);

NETVFS_EXPORT QVariantMap pinOptions(const ServerIdentity &identity);

}
#endif
