// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SERVICEPOLICY_H
#define NETVFS_SERVICEPOLICY_H

#include "error.h"
#include "types.h"

namespace NetVfs {

// SPEC-v2 XA-1, XA-4: the account services a configuration is used for.
// Backup is the "<provider>-backup" service (type "storage", Buteo); Files
// is "<provider>-files" (type "netvfs-files", file browsing through the
// bridge and other consumers).
enum class Service { Backup, Files };

NETVFS_EXPORT QString serviceName(const QString &provider, Service service);
NETVFS_EXPORT QString serviceId(Service service);           // "backup" | "files"
// false for anything but "backup" or "files".
NETVFS_EXPORT bool serviceFromId(const QString &id, Service *service);

// Option keys of ConnectionParams::options, stored as "netvfs/<provider>/<key>"
// (SPEC 6.2, SPEC-v2 XA-3).
namespace OptionKeys {
NETVFS_EXPORT extern const char HostKey[];          // SSH host key pin (XC-16)
NETVFS_EXPORT extern const char AuthMode[];         // password | publickey | interactive (sftp)
NETVFS_EXPORT extern const char SecurityProfile[];  // smb: strict | signed | guest (XM-1)
NETVFS_EXPORT extern const char Share[];            // smb; empty: server mode (XM-2)
NETVFS_EXPORT extern const char Shares[];           // smb: string list of saved shares (XM-3)
NETVFS_EXPORT extern const char ShowAdminShares[];  // smb (XM-7)
NETVFS_EXPORT extern const char AllowInsecure[];    // consent to an unprotected or weakened transport
} // namespace OptionKeys

// SMB security profiles (XM-1).
namespace SecurityProfiles {
NETVFS_EXPORT extern const char Strict[];
NETVFS_EXPORT extern const char Signed[];
NETVFS_EXPORT extern const char Guest[];
} // namespace SecurityProfiles

// The SMB profile in effect: security_profile when set, else "strict".
// Empty for other providers. The value is returned as stored (an unknown profile is
// refused by checkServicePolicy()).
NETVFS_EXPORT QString securityProfile(const ConnectionParams &params);

// A configuration whose transport is unprotected or weakened and so needs
// the account's consent (allow_insecure=true): the SMB profile guest.
NETVFS_EXPORT bool isInsecureConfiguration(const ConnectionParams &params);

// SPEC-v2 XA-4, the "allowed for service" column of XM-1 (amends SEC-2, M-4,
// M-8 as in SPEC-v2-review 2.1, 2.9):
//
//  | Configuration                                | Backup | Files                  |
//  |----------------------------------------------|--------|------------------------|
//  | smb strict, signed                           | yes    | yes                    |
//  | smb guest                                    | no     | with allow_insecure    |
//  | smb unknown profile                          | no     | no                     |
//  | smb without a share (server mode)            | no     | yes                    |
//  | allow_insecure=true (any provider)           | no     | yes                    |
//  | auth_mode=interactive (needs a person)       | no     | yes                    |
//  | anything else                                | yes    | yes                    |
//
// A refused configuration is SecurityPolicy with a message naming the reason.
NETVFS_EXPORT Result checkServicePolicy(const ConnectionParams &params, Service service);

// SPEC-v2 XA-7 (and SPEC-v2-review 2.15): accounts that legitimately have no
// stored secret: auth_mode=interactive (the person answers the prompts) and
// the smb guest profile.
NETVFS_EXPORT bool secretOptional(const ConnectionParams &params);

// The options to store when the user accepts `identity` (XC-16): host_key.
NETVFS_EXPORT QVariantMap pinOptions(const ServerIdentity &identity);

} // namespace NetVfs

#endif
