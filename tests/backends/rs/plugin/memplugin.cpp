// SPDX-License-Identifier: LGPL-2.1-or-later
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

}

#include "memplugin.moc"
