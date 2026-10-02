// SPDX-License-Identifier: LGPL-2.1-or-later
#include "loader.h"
#include "backupclient.h"

#include <memory>

Buteo::ClientPlugin *NetVfsButeoLoader::createClientPlugin(const QString &pluginName,
                                                           const Buteo::SyncProfile &profile,
                                                           Buteo::PluginCbInterface *cbInterface)
{
    // Ownership passes to the Buteo plugin runner.
    return std::make_unique<NetVfs::BackupClient>(QStringLiteral(NETVFS_BUTEO_PROVIDER),
                                                  NetVfs::BackupClient::Operation::NETVFS_BUTEO_OPERATION,
                                                  pluginName, profile, cbInterface)
        .release();
}
