// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpplugin.h"
#include "rsbackend.h"
#include "rskeytools.h"

namespace NetVfs {

QString SftpPlugin::provider() const
{
    return QStringLiteral("sftp");
}

Result SftpPlugin::create(Backend **out)
{
    return Rs::createBackend(provider(), out);
}

Result SftpPlugin::generate(SshKeyMaterial *out)
{
    return Rs::RsKeyTools().generate(out);
}

Result SftpPlugin::importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out)
{
    return Rs::RsKeyTools().importKey(fileContents, passphrase, out);
}

Result SftpPlugin::describe(const QByteArray &privateKey, SshKeyMaterial *out)
{
    return Rs::RsKeyTools().describe(privateKey, out);
}

} // namespace NetVfs
