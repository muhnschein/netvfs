// SPDX-License-Identifier: LGPL-2.1-or-later
// netvfs-accounts (SPEC-v2 XB-2a): the bridge's access to the accounts
// database, installed setgid `privileged`. One request per run, from the
// arguments; the answer goes to stdout (accountshelper.h).
#include "accountshelper.h"
#include "privileges.h"

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
    // Before anything reads the environment, Qt and libaccounts included.
    if (NetVfs::Bridge::runningSetId() && !NetVfs::Bridge::prepareSetIdProcess()) {
        std::fputs("netvfs-accounts: the user has no home folder\n", stderr);
        return 1;
    }
    QCoreApplication app(argc, argv);
    const QStringList arguments = QCoreApplication::arguments().mid(1);
    Accounts::Manager manager;
    return writeAll(NetVfs::Bridge::AccountsHelper::serve(&manager, arguments)) ? 0 : 1;
}
