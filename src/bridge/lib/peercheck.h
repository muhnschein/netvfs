// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_PEERCHECK_H
#define NETVFS_BRIDGE_PEERCHECK_H

#include "error.h"

#include <QtCore/QString>

#include <functional>

#include <sys/types.h>

// SPEC-v2 XB-5: who is on the other end of the socket.
//
// 1. SO_PEERCRED of the connected socket: the uid must be the bridge's own.
// 2. The peer's executable must be the registered one. /proc/<pid>/exe is
//    opened (the magic link opens the file the peer runs, across mount
//    namespaces, so a path cannot fake it) and compared with Executable by
//    identity (device and inode). Sailjail starts apps with firejail
//    --private-bin, which runs a copy of the binary from a tmpfs bind-mounted
//    over /usr/bin: another inode. A different file is therefore accepted
//    when it has the same size and the same bytes, read
//    from the descriptor opened in step 3's window (chunked, bounded memory).
// 3. Pid reuse: the pid in SO_PEERCRED belongs to the process that connected.
//    If that process exited and its pid was reused before the check, the
//    check must not succeed. Where the kernel has pidfds (SO_PEERPIDFD,
//    Linux 6.5, gives the connecting process itself; pidfd_open, Linux 5.3,
//    pins the pid from then on) the check holds a pidfd while it reads /proc
//    and verifies afterwards that the pidfd's process is still alive with that
//    pid (Pid: line of /proc/self/fdinfo/<pidfd>). In every case the process
//    start time (/proc/<pid>/stat field 22) must be the same before and after
//    opening exe and must not be later than the moment the connection was
//    accepted, so a process started after the connection cannot pass for it.
// The peer's /proc entries are read with the real gid as fsgid: the bridge
// is setgid `privileged` (XB-2), and the kernel lets only a process with the
// peer's gid open its exe.
//
// /proc, the credentials and the clock are injectable for tests.
namespace NetVfs::Bridge {

struct PeerCredentials {
    pid_t pid = 0;
    uid_t uid = 0;
    int pidfd = -1;                   // from SO_PEERPIDFD, owned by the caller; -1 if none
};

class PeerChecker
{
public:
    struct Environment {
        QString procRoot = QStringLiteral("/proc");
        uid_t ownUid = 0;                                   // default: geteuid()
        // Credentials of a connected socket; default: SO_PEERCRED (+ SO_PEERPIDFD).
        std::function<bool(int fd, PeerCredentials *out)> credentials;
        // pidfd_open(); default: the syscall where available, else -1.
        std::function<int(pid_t pid)> openPidfd;
        // Clock ticks since boot "now" (to compare with the start time);
        // default: /proc/uptime * sysconf(_SC_CLK_TCK).
        std::function<qint64()> bootTicksNow;
        // Called after exe was opened, between the first and the second
        // start time read (tests simulate pid reuse there).
        std::function<void()> afterExeRead;
    };

    // `executable` is the registered Executable of the consumer.
    explicit PeerChecker(const QString &executable);
    PeerChecker(const QString &executable, const Environment &environment);

    // Success, or PermissionDenied with the reason (for the warning log).
    Result check(int socketFd) const;
    // The same for already known credentials.
    Result checkCredentials(const PeerCredentials &credentials) const;

    static bool systemCredentials(int fd, PeerCredentials *out);

private:
    Result checkProcess(pid_t pid, int pidfd) const;
    QString procPath(pid_t pid, const char *leaf) const;
    bool startTime(pid_t pid, qint64 *ticks) const;
    bool pidfdAlive(int pidfd, pid_t pid) const;

    QString m_executable;
    Environment m_env;
};

} // namespace NetVfs::Bridge

#endif
