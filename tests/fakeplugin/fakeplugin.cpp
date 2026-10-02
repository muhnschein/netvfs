// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"

#include <QtCore/QObject>

class FakeBackendFactory : public QObject, public NetVfs::BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/1.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override { return QStringLiteral("fake"); }
    NetVfs::Backend *create() override { return new NetVfs::Test::FakeBackend; }
};

#include "fakeplugin.moc"
