// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSKEYTOOLS_H
#define NETVFS_RSKEYTOOLS_H

#include "sshkeys.h"

namespace NetVfs::Rs {

// SshKeyTools over the key functions of libnetvfs-rs.so, for the SFTP plugin's root object. Without
// the library each call is Internal.
class RsKeyTools : public SshKeyTools
{
public:
    Result generate(SshKeyMaterial *out) override;
    Result importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out) override;
    Result describe(const QByteArray &privateKey, SshKeyMaterial *out) override;
};

}
#endif
