// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SSHKEYTOOLS_H
#define NETVFS_SSHKEYTOOLS_H

#include "sshkeys.h"

namespace NetVfs::Sftp {

// SPEC-sftp 5.1; see SshKeyTools for the contract.
Result generateKey(SshKeyMaterial *out);
Result importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out);
Result describeKey(const QByteArray &privateKey, SshKeyMaterial *out);

constexpr const char *PublicKeyComment = "sailfish-backup";

} // namespace NetVfs::Sftp

#endif
