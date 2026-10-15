// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rsbackend.h"
#include "rskeytools.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-sftp.so: provider "sftp" of the Rust backends
// and, so that the SSH code lives only in the SFTP package, the SSH key
// tools (SPEC-sftp 5.1).
class SftpPlugin : public QObject, public BackendFactory, public Rs::RsKeyTools
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory")
    Q_INTERFACES(NetVfs::BackendFactory NetVfs::SshKeyTools)

public:
    QString provider() const override { return QStringLiteral("sftp"); }
    Result create(Backend **out) override { return Rs::createBackend(provider(), out); }
};

} // namespace NetVfs

#include "sftpplugin.moc"
