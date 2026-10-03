// SPDX-License-Identifier: LGPL-2.1-or-later
// /usr/libexec/netvfs/netvfs-bridge <consumer-id> (SPEC-v2 XB-2).
//
// Started by systemd user socket activation (netvfs-bridge@<id>.socket,
// Accept=no). libdbus adopts the activated listening socket through the
// "systemd:" address (sd_listen_fds protocol, LISTEN_PID/LISTEN_FDS), so the
// rendezvous stays exactly the socket systemd created in the consumer's
// folder (XB-4). --listen ADDRESS replaces it for development and tests.
#include "bridgelog.h"
#include "bridgeserver.h"
#include "consentstore.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QStringList>

#include <cstdio>

namespace {

int usage()
{
    std::fprintf(stderr, "usage: netvfs-bridge [--listen DBUS-ADDRESS] <consumer-id>\n");
    return 2;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("netvfs-bridge"));
    QStringList args = QCoreApplication::arguments().mid(1);

    NetVfs::Bridge::BridgeConfig config;
    if (args.size() >= 2 && args.at(0) == QLatin1String("--listen")) {
        config.listenAddress = args.at(1);
        args = args.mid(2);
    }
    if (args.size() != 1)
        return usage();

    const QString id = args.at(0);
    if (const NetVfs::Result r = NetVfs::ConsentStore::loadConsumer(id, &config.consumer); !r.ok()) {
        qCCritical(lcNetVfsBridge).noquote() << NetVfs::Bridge::consumerTag(id) << r.message();
        return 1;
    }

    // Tests shorten the 30 s idle exit (XB-2).
    bool ok = false;
    if (const int idleMs = qEnvironmentVariableIntValue("NETVFS_BRIDGE_IDLE_EXIT_MS", &ok); ok && idleMs > 0)
        config.idleExitMs = idleMs;

    NetVfs::Bridge::BridgeServer server(config);
    if (const NetVfs::Result r = server.start(); !r.ok()) {
        qCCritical(lcNetVfsBridge).noquote() << server.tag() << r.message();
        return 1;
    }
    QObject::connect(&server, &NetVfs::Bridge::BridgeServer::idleTimeout, &app, &QCoreApplication::quit);
    return QCoreApplication::exec();
}
