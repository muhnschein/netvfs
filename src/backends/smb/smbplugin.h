// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBPLUGIN_H
#define NETVFS_SMBPLUGIN_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs::Smb {

// Root object of libnetvfs-smb.so.
class SmbBackendFactory : public QObject, public BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/1.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override;
    Backend *create() override;
};

} // namespace NetVfs::Smb

#endif
