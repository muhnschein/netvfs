// SPDX-License-Identifier: LGPL-2.1-or-later
// Root object of libnetvfs-mem.so: provider "mem" of libnetvfs-rs.so through
// the shim, with its key tools, as a Rust protocol's plugin will be.
#include "rsbackend.h"
#include "rskeytools.h"

#include <QtCore/QObject>

namespace NetVfs {

class MemPlugin : public QObject, public BackendFactory, public Rs::RsKeyTools
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory")
    Q_INTERFACES(NetVfs::BackendFactory NetVfs::SshKeyTools)

public:
    QString provider() const override { return QStringLiteral("mem"); }
    Result create(Backend **out) override { return Rs::createBackend(provider(), out); }
};

} // namespace NetVfs

#include "memplugin.moc"
