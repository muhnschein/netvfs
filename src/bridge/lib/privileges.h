// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_PRIVILEGES_H
#define NETVFS_BRIDGE_PRIVILEGES_H

#include <QtCore/QByteArray>
#include <QtCore/QList>

// SPEC-v2 XB-2a: netvfs-accounts is installed setgid `privileged`, and any
// process of any user can start it. The kernel marks it AT_SECURE: glibc
// drops LD_* and a few other variables, and the process is not dumpable.
// The rest of its environment is still the caller's.
namespace NetVfs::Bridge {

// The kernel started this process with AT_SECURE (set-id exec).
bool runningSetId();

// Whether a variable survives prepareSetIdProcess(): locale, time zone and
// the session bus (libaccounts announces a change there). Everything else
// could make the privileged process read or write another database (HOME,
// XDG_*_HOME, ACCOUNTS, AG_*) or load code chosen by its caller (QT_*,
// GIO_*, ...).
bool keptInSetIdProcess(const QByteArray &name);

// First thing in main() of a set-id process: removes the other variables
// (returns their names), sets HOME to the home folder of the real uid
// (passwd), where libaccounts finds that user's database, and a missing
// XDG_RUNTIME_DIR to /run/user/<uid> when that is the uid's folder (GLib's
// session bus, without which libaccounts opens no database). The soft core
// limit becomes 0: a core file would be the user's and hold memory of the
// `privileged` group. False when the real uid has no home folder.
bool prepareSetIdProcess(QList<QByteArray> *removed = nullptr);

} // namespace NetVfs::Bridge

#endif
