// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackend.h"
#include "names.h"

#include <QtCore/QFile>
#include <QtCore/QMutexLocker>
#include <QtCore/QObject>

#include <mutex>

namespace {

using NetVfs::Test::FakeServer;

QString keyOfHex(const QByteArray &hex)
{
    return FakeServer::keyFor(NetVfs::Names::decode(QByteArray::fromHex(hex)));
}

// One line of a seed file (server mutex held); unknown lines are ignored.
void seedLine(FakeServer *server, const QByteArray &line)
{
    const QList<QByteArray> words = line.simplified().split(' ');
    const QByteArray &kind = words.first();
    if (kind == "file" && words.size() == 3) {
        server->addFile(keyOfHex(words.at(1)), QByteArray::fromHex(words.at(2)));
    } else if (kind == "dir" && words.size() == 2) {
        server->addDir(keyOfHex(words.at(1)));
    } else if (kind == "credentials" && (words.size() == 2 || words.size() == 3)) {
        server->userName = QString::fromUtf8(words.at(1));
        server->secret = QByteArray::fromHex(words.value(2));
    } else if (kind == "identity" && words.size() > 1) {
        // The pin itself holds a space: "<algorithm> <base64 key>".
        server->identity = NetVfs::ServerIdentity::fromPin(QString::fromUtf8(line.simplified().mid(kind.size() + 1)));
    }
}

// Design §4.1: NETVFS_FAKE_SEED=<file> prepares the FakeServer of a process
// a test starts (the bridge binary), on the first backend created. Lines:
//   file <path-hex> <data-hex>
//   dir <path-hex>
//   credentials <user> [<secret-hex>]   (without one, the secret is empty)
//   identity <pin>
void seedFromEnvironment()
{
    const QByteArray path = qgetenv("NETVFS_FAKE_SEED");
    if (path.isEmpty())
        return;
    QFile file(QString::fromLocal8Bit(path));
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning("NETVFS_FAKE_SEED: cannot read %s", path.constData());
        return;
    }
    FakeServer *server = FakeServer::instance();
    QMutexLocker lock(&server->mutex);
    while (!file.atEnd()) {
        if (const QByteArray line = file.readLine().trimmed(); !line.isEmpty())
            seedLine(server, line);
    }
}

} // namespace

class FakeBackendFactory : public QObject, public NetVfs::BackendFactory
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.netvfs.BackendFactory/2.0")
    Q_INTERFACES(NetVfs::BackendFactory)

public:
    QString provider() const override { return QStringLiteral("fake"); }
    NetVfs::Backend *create() override
    {
        static std::once_flag seeded;
        std::call_once(seeded, seedFromEnvironment);
        return new NetVfs::Test::FakeBackend;
    }
};

#include "fakeplugin.moc"
