// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-accounts (SPEC-v2 XB-2a): the bridge's access to the accounts
// database, installed setgid `privileged`. One request per run, from the
// arguments; the answer goes to stdout (accountshelper.h). Confined as
// sandbox.h describes, set-id or not, so that the tests run it confined too.
#include "accountshelper.h"
#include "privileges.h"
#include "sandbox.h"

#include <Accounts/Manager>

#include <QtCore/QCoreApplication>
#include <QtCore/QStringList>

#include <cerrno>
#include <cstdio>

#include <unistd.h>

namespace {

bool writeAll(const QByteArray &bytes)
{
    int done = 0;
    while (done < bytes.size()) {
        const ssize_t n = ::write(STDOUT_FILENO, bytes.constData() + done, static_cast<size_t>(bytes.size() - done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += int(n);
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    using namespace NetVfs::Bridge;
    // Before anything opens a file or reads the environment, Qt and
    // libaccounts included.
    if (!sanitizeDescriptors())
        return 1;
    resetProcessState();
    const bool setId = runningSetId();
    if (setId && !prepareSetIdProcess()) {
        std::fputs("netvfs-accounts: the user has no home folder\n", stderr);
        return 1;
    }
    // Before Qt or GLib start a thread, which Landlock (without TSYNC) and
    // this seccomp filter would not cover. GLib finds a set-id process's
    // session bus below the runtime folder, never on an abstract socket.
    restrictFilesystem(accountsDirectories(),
                       !setId && qgetenv("DBUS_SESSION_BUS_ADDRESS").contains("abstract="));
    restrictSyscalls();

    QByteArray answer;
    {
        QCoreApplication app(argc, argv);
        const QStringList arguments = QCoreApplication::arguments().mid(1);
        Accounts::Manager manager;
        answer = AccountsHelper::serve(&manager, arguments);
    }
    // Writing the answer needs no group.
    if (!dropSetIdGroup()) {
        std::fputs("netvfs-accounts: cannot drop the group\n", stderr);
        return 1;
    }
    return writeAll(answer) ? 0 : 1;
}
