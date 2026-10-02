// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_FTPPLUGIN_H
#define NETVFS_FTPPLUGIN_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-ftp.so (SPEC-v2 6.4). Declared in a header that
// pulls in no backend headers: Qt 5.6 moc cannot parse the C++17 nested
// namespace definitions used there.
class FtpBackendFactory : public QObject, public BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/2.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override;
    Backend *create() override;
};

} // namespace NetVfs

#endif
