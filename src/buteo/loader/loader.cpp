// SPDX-License-Identifier: LGPL-2.1-or-later
// The single loader source of all Buteo plugins (SPEC 8.1). Each plugin
// compiles it with its own provider, operation and plugin IID (plugin.pri).
#include "backupclient.h"

#include <SyncPluginLoader.h>

class NetVfsButeoLoader : public Buteo::SyncPluginLoader
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID NETVFS_BUTEO_LOADER_IID)
    Q_INTERFACES(Buteo::SyncPluginLoader)

public:
    Buteo::ClientPlugin *createClientPlugin(const QString &pluginName, const Buteo::SyncProfile &profile,
                                            Buteo::PluginCbInterface *cbInterface) override
    {
        return new NetVfs::BackupClient(QStringLiteral(NETVFS_BUTEO_PROVIDER),
                                        NetVfs::BackupClient::Operation::NETVFS_BUTEO_OPERATION,
                                        pluginName, profile, cbInterface);
    }
};

#include "loader.moc"
