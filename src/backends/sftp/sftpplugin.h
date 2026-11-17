// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SFTPPLUGIN_H
#define NETVFS_SFTPPLUGIN_H

#include "backend.h"
#include "sshkeys.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-sftp.so: provider "sftp" of the Rust backends plus the SSH key tools.
// Shim stays out of this header: Qt 5.6 moc cannot parse C++17 nested namespaces.
class SftpPlugin : public QObject, public BackendFactory, public SshKeyTools
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory")
    Q_INTERFACES(NetVfs::BackendFactory NetVfs::SshKeyTools)

public:
    QString provider() const override;
    Result create(Backend **out) override;

    Result generate(SshKeyMaterial *out) override;
    Result importKey(const QByteArray &fileContents, const QByteArray &passphrase, SshKeyMaterial *out) override;
    Result describe(const QByteArray &privateKey, SshKeyMaterial *out) override;
};

}
#endif
