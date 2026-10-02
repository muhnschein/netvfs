// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"

#include <QtCore/QObject>

// Implements the current interface but declares the v1 IID, as a plugin
// built against the old headers would. The loader must refuse it (XC-1).
class OldIidBackendFactory : public QObject, public NetVfs::BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/1.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override { return QStringLiteral("oldiid"); }
    NetVfs::Backend *create() override { return new NetVfs::Test::FakeBackend; }
};

#include "oldplugin.moc"
