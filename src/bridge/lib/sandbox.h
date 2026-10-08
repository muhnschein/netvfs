// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_SANDBOX_H
#define NETVFS_BRIDGE_SANDBOX_H

#include <QtCore/QByteArray>
#include <QtCore/QList>

// SPEC-v2 XB-2a: the confinement of netvfs-accounts, which any process of the
// user can start with the group `privileged`. In main(), before Qt or
// libaccounts start a thread: sanitizeDescriptors(), resetProcessState(),
// prepareSetIdProcess() (privileges.h), then restrictFilesystem() and
// restrictSyscalls(). After the database work: dropSetIdGroup().
//
// Landlock and seccomp are best-effort: the Jolla Phone 2026 kernel (6.12)
// has seccomp but no Landlock, a later kernel may have both.
namespace NetVfs::Bridge {

// fds 0, 1 and 2 open (to /dev/null when the caller closed them, so that no
// file the helper opens becomes its stdout), every other inherited descriptor
// closed. False when /dev/null cannot be opened.
bool sanitizeDescriptors();

// umask 077, default signal handlers and an empty signal mask, and the file
// size soft limit raised to the hard one (a caller's small limit would cut the
// attention write short).
void resetProcessState();

// Where libaccounts keeps the database, for restrictFilesystem(): ACCOUNTS
// when set (tests, never in a set-id process), else the Sailfish OS folder
// (XDG_DATA_HOME/system/privileged/Accounts) and the upstream one
// (XDG_CONFIG_HOME/libaccounts-glib), both from HOME when unset.
QList<QByteArray> accountsDirectories();

// The Landlock ABI versions this code knows; it uses what the kernel offers
// of them: 1 files, 2 renames and links across folders, 3 truncation, 4 TCP,
// 5 device ioctls, 6 abstract unix sockets and signals beyond the sandbox,
// 7 audit logging of denials (on by default, nothing to set).
constexpr int LandlockNewestAbi = 7;

struct FilesystemRestriction {
    int abi = 0;          // the kernel's Landlock ABI, 0 without Landlock
    bool enforced = false;
};

// Landlock: reads only below the system folders (/usr, /etc, /lib*, /proc),
// the runtime folder and libaccounts' provider folders; reads and writes only
// below `writable` and /dev/null; executes nothing; with ABI 4 connects and
// binds no TCP port; with ABI 6 signals no process and connects to no
// abstract unix socket outside the sandbox (unless `allowAbstractSockets`:
// the session bus of a test may be one). Without Landlock, nothing happens
// and `enforced` is false; a kernel that has it but refuses the rules is
// reported on stderr.
FilesystemRestriction restrictFilesystem(const QList<QByteArray> &writable, bool allowAbstractSockets);

// no_new_privs and a seccomp filter that fails these with EPERM: exec,
// ptrace (unless built with AddressSanitizer, whose leak check needs it),
// sockets other than AF_UNIX, new namespaces, mounts, modules, kexec, BPF,
// io_uring, userfaultfd, perf, keyrings, file handles; and any chmod, open,
// mkdir or mknod that would set a setuid or setgid bit (a file of the group
// `privileged` left behind with it would hand the group to anyone).
// clone3 fails with ENOSYS so that glibc falls back to clone, whose flags the
// filter can see. False when the kernel or the architecture has no seccomp.
bool restrictSyscalls();

// Gives up the group of a set-id start for good: real, effective and saved
// gid become the real one. False if any of them is still another.
bool dropSetIdGroup();

} // namespace NetVfs::Bridge

#endif
