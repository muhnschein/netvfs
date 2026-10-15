// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOCALPLUGIN_H
#define NETVFS_LOCALPLUGIN_H

#include "backend.h"

#include <QtCore/QObject>

namespace NetVfs {

// Root object of libnetvfs-local.so (SPEC-v2 section 6.3). (A single-level
// namespace: Qt 5.6 moc cannot parse C++17 nested namespace definitions.)
class LocalBackendFactory : public QObject, public BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override;
    Result create(Backend **out) override;
};

} // namespace NetVfs

#endif
