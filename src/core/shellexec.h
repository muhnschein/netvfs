// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SHELLEXEC_H
#define NETVFS_SHELLEXEC_H

#include "backend.h"

#include <QtCore/QStringList>

namespace NetVfs {

// SPEC-v2 XS-9: running commands on the server, as an extension interface
// next to Backend (not part of it). Only the SFTP backend implements it, and
// only when the account sets allow_shell=true and the server grants an exec
// channel; Capabilities then report ShellExec.
//
// Getting it from a backend (after authenticate()):
//
//     if (ShellExec *shell = ShellExec::of(backend)) {
//         ExecResult result;
//         Result r = shell->exec({ QStringLiteral("du"), QStringLiteral("-s"), path }, ExecOptions(), &result);
//     }
//
// ShellExec::of() is a dynamic_cast plus the capability check; a backend
// that implements the interface but did not report ShellExec answers every
// call with Unsupported. Calls follow the backend's rules: same thread,
// blocking, cancel() ends them with Canceled within 2 s (C-9).
struct ExecOptions {
    qint64 maxOutput = 1 << 20;   // per stream; more is dropped and `truncated` set
    int timeoutMs = -1;           // -1: the connection's request timeout (C-14); 0: none
};

struct ExecResult {
    int exitStatus = -1;          // -1: ended by a signal, or no status reported
    QByteArray out;
    QByteArray err;
    bool truncated = false;       // output beyond maxOutput was dropped
};

class NETVFS_EXPORT ShellExec
{
public:
    virtual ~ShellExec();

    // Runs argv[0] with the arguments argv[1..]. netvfs quotes every
    // element with POSIX single-quote rules, so nothing in argv is
    // interpreted by the server's shell (which must be POSIX compatible).
    // Paths in argv are backend paths as given (not resolved against the
    // start directory). A command that ran is success whatever its exit
    // status; *result tells.
    virtual Result exec(const QStringList &argv, const ExecOptions &options, ExecResult *result) = 0;

    // serverFind: `find` below `dir` (a backend path) for names matching the
    // glob `namePattern` (find -name), with a fixed command template and a
    // defensive parser. Returns at most `maxResults` backend paths below
    // `dir`, in the server's order.
    virtual Result find(const QString &dir, const QString &namePattern, int maxResults, QStringList *paths) = 0;

    // The interface of `backend` when it reports Capability::ShellExec,
    // else nullptr.
    static ShellExec *of(Backend *backend);
};

} // namespace NetVfs

Q_DECLARE_INTERFACE(NetVfs::ShellExec, "org.netvfs.ShellExec/1.0")

#endif
