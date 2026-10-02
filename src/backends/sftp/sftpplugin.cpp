// SPDX-License-Identifier: LGPL-2.1-or-later
#include "sftpbackend.h"
#include "sshkeytools.h"

#include <QtCore/QObject>

#include <memory>

namespace NetVfs::Sftp {

// Root object of libnetvfs-sftp.so: the backend factory and, so that libssh
// code lives only in the SFTP package, the SSH key tools (SPEC-sftp 5.1).
class SftpPlugin : public QObject, public BackendFactory, public SshKeyTools
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/1.0")
    Q_INTERFACES(NetVfs::BackendFactory NetVfs::SshKeyTools)

public:
    QString provider() const override { return QStringLiteral("sftp"); }
    Backend *create() override { return std::make_unique<SftpBackend>().release(); }

    Result generate(SshKeyMaterial *out) override { return generateKey(out); }
    Result importKey(const QByteArray &fileContents, const QByteArray &passphrase,
                     SshKeyMaterial *out) override
    {
        return Sftp::importKey(fileContents, passphrase, out);
    }
    Result describe(const QByteArray &privateKey, SshKeyMaterial *out) override
    {
        return describeKey(privateKey, out);
    }
};

} // namespace NetVfs::Sftp

#include "sftpplugin.moc"
