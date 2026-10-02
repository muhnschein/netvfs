// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBPLUGIN_H
#define NETVFS_SMBPLUGIN_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-smb.so. (A single-level namespace: Qt 5.6 moc
// cannot parse C++17 nested namespace definitions.)
class SmbBackendFactory : public QObject, public BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/1.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override;
    Backend *create() override;
};

} // namespace NetVfs

#endif
