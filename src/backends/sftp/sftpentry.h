// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPENTRY_H
#define NETVFS_SFTPENTRY_H

#include "sshkeys.h"

// What the plugin root object (sftpplugin.cpp) needs from the backend. This
// header and everything it includes must stay readable by the moc of the
// target's Qt 5.6, which rejects C++17 nested namespace definitions.
namespace NetVfs {

Backend *createSftpBackend();
Result generateSshKey(SshKeyMaterial *out);
Result importSshKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out);
Result describeSshKey(const QByteArray &privateKey, SshKeyMaterial *out);

} // namespace NetVfs

#endif
