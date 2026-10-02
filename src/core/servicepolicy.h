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
NETVFS_EXPORT extern const char HostKey[];          // SSH and TLS pins (XC-16)
NETVFS_EXPORT extern const char TlsVerifyPeer[];    // with a TLS pin: pinned certificate was system trusted (W-4)
NETVFS_EXPORT extern const char PinTrusted[];       // webdav, ftp: pin even a system-trusted certificate
NETVFS_EXPORT extern const char AuthMode[];         // password | publickey | interactive (sftp) | token (webdav)
NETVFS_EXPORT extern const char SecurityProfile[];  // smb: strict | signed | legacy | guest (XM-1)
NETVFS_EXPORT extern const char RequireEncryption[];// smb, v1 (M-3): false maps to "signed"
NETVFS_EXPORT extern const char Share[];            // smb; empty: server mode (XM-2)
NETVFS_EXPORT extern const char Shares[];           // smb: string list of saved shares (XM-3)
NETVFS_EXPORT extern const char ShowAdminShares[];  // smb (XM-7)
NETVFS_EXPORT extern const char BasePath[];         // webdav
NETVFS_EXPORT extern const char Tls[];              // webdav: https | http
NETVFS_EXPORT extern const char Flavor[];           // webdav: auto | nextcloud | generic
NETVFS_EXPORT extern const char TlsMode[];          // ftp: explicit | implicit | none
NETVFS_EXPORT extern const char AllowInsecure[];    // consent to an unprotected or weakened transport
NETVFS_EXPORT extern const char AllowShell[];       // sftp: exec channel (XS-9), never for backups
} // namespace OptionKeys

// SMB security profiles (XM-1).
namespace SecurityProfiles {
NETVFS_EXPORT extern const char Strict[];
NETVFS_EXPORT extern const char Signed[];
NETVFS_EXPORT extern const char Legacy[];
NETVFS_EXPORT extern const char Guest[];
} // namespace SecurityProfiles

// The SMB profile in effect: security_profile when set, else "signed" for
// the v1 option require_encryption=false and "strict" otherwise. Empty for
// other providers. The value is returned as stored (an unknown profile is
// refused by checkServicePolicy()).
NETVFS_EXPORT QString securityProfile(const ConnectionParams &params);

// A configuration whose transport is unprotected or weakened and so needs
// the account's consent (allow_insecure=true): WebDAV over plain HTTP, FTP
// without TLS, SMB profiles legacy and guest.
NETVFS_EXPORT bool isInsecureConfiguration(const ConnectionParams &params);

// SPEC-v2 XA-4, the "allowed for service" column of XM-1 (amends SEC-2, M-4,
// M-8, S-3 as in SPEC-v2-review 2.1, 2.5, 2.9):
//
//  | Configuration                                | Backup | Files                  |
//  |----------------------------------------------|--------|------------------------|
//  | smb strict, signed                           | yes    | yes                    |
//  | smb legacy, guest                            | no     | with allow_insecure    |
//  | smb unknown profile                          | no     | no                     |
//  | smb without a share (server mode)            | no     | yes                    |
//  | webdav tls=http, ftp tls_mode=none           | no     | with allow_insecure    |
//  | allow_insecure=true (any provider)           | no     | yes                    |
//  | auth_mode=interactive (needs a person)       | no     | yes                    |
//  | anything else                                | yes    | yes                    |
//
// A refused configuration is SecurityPolicy with a message naming the reason.
NETVFS_EXPORT Result checkServicePolicy(const ConnectionParams &params, Service service);

// The parameters a service gets: for Backup, allow_shell is removed (S-3 as
// amended: the exec channel is never used for backups).
NETVFS_EXPORT ConnectionParams paramsForService(const ConnectionParams &params, Service service);

// SPEC-v2 XA-7 (and SPEC-v2-review 2.15): accounts that legitimately have no
// stored secret: auth_mode=interactive (the person answers the prompts) and
// the smb guest profile. Token accounts store their token as the secret.
NETVFS_EXPORT bool secretOptional(const ConnectionParams &params);

// The options to store when the user accepts `identity` (XC-16): host_key,
// and for a TLS identity also tls_verify_peer = identity.systemTrusted (W-4:
// the backend keeps chain and host name verification on only for a pin of a
// certificate that was system trusted when it was pinned).
NETVFS_EXPORT QVariantMap pinOptions(const ServerIdentity &identity);

} // namespace NetVfs

#endif
