// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpbackend.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-ftp.so (SPEC-v2 6.4).
class FtpBackendFactory : public QObject, public BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/2.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override { return QStringLiteral("ftp"); }
    Backend *create() override { return Ftp::createFtpBackend(); }
};

} // namespace NetVfs

#include "ftpplugin.moc"
