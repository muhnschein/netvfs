// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpentry.h"
#include "sftpbackend.h"
#include "sshkeytools.h"

#include <memory>

namespace NetVfs {

Backend *createSftpBackend()
{
    return std::make_unique<Sftp::SftpBackend>().release();
}

Result generateSshKey(SshKeyMaterial *out)
{
    return Sftp::generateKey(out);
}

Result importSshKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out)
{
    return Sftp::importKey(fileContents, passphrase, out);
}

Result describeSshKey(const QByteArray &privateKey, SshKeyMaterial *out)
{
    return Sftp::describeKey(privateKey, out);
}

} // namespace NetVfs
