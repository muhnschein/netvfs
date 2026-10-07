// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_PRIVILEGES_H
#define NETVFS_BRIDGE_PRIVILEGES_H

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtDBus/QDBusConnection>

#include <sys/types.h>

// SPEC-v2 XB-2: netvfs-bridge is installed setgid `privileged`, because the
// Sailfish OS accounts database is readable by that group only. The kernel
// marks such a process AT_SECURE: glibc drops LD_* and a few other
// variables, GLib and upstream libdbus ignore DBUS_SESSION_BUS_ADDRESS, and
// the process is not dumpable (its own /proc entries belong to root).
namespace NetVfs::Bridge {

// The kernel started this process with AT_SECURE (setgid exec).
bool runningSetId();

// Whether a variable survives prepareSetIdProcess(): what the bridge needs
// from the systemd user manager (home, locale, runtime folder, session bus,
// socket activation, logging rules). Everything else, the NETVFS_* test
// overrides and every library or plugin search path among them, could make
// the privileged process load or run code chosen by its caller.
bool keptInSetIdProcess(const QByteArray &name);

// First thing in main() of a set-id process: removes the other variables
// (returns their names), sets XDG_RUNTIME_DIR to /run/user/<uid> when it is
// missing, and makes the process dumpable again so that it can read its own
// /proc/self/fdinfo (pidfds, XB-5) on kernels before 5.14. Dumpable does not
// let other processes of the user in: ptrace access also needs their gids to
// match the bridge's `privileged` effective gid. The soft core limit becomes
// 0, so that a crash leaves no user-readable core with privileged memory.
QList<QByteArray> prepareSetIdProcess();

// "unix:path=<runtimeRoot>/<uid>/bus" when that is a socket owned by `uid`,
// else empty.
QString userBusAddress(const QString &runtimeRoot, uid_t uid);

// The session bus. QDBusConnection::sessionBus() asks libdbus, which in an
// AT_SECURE process ignores the environment unless it is patched not to (the
// Sailfish OS one is); then the user bus of the real uid is used directly.
QDBusConnection sessionBus();

} // namespace NetVfs::Bridge

#endif
