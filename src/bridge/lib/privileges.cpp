// SPDX-License-Identifier: LGPL-2.1-or-later
#include "privileges.h"

#include <cstdlib>

#include <pwd.h>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace NetVfs::Bridge {

namespace {

const char RuntimeRoot[] = "/run/user";

const char *const KeptVariables[] = {
    "LANG", "LANGUAGE", "TZ", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
};

bool ownedDirectory(const QByteArray &path, uid_t uid)
{
    struct stat st {};
    return ::lstat(path.constData(), &st) == 0 && st.st_uid == uid && S_ISDIR(st.st_mode);
}

} // namespace

bool runningSetId()
{
    return ::getauxval(AT_SECURE) != 0;
}

bool keptInSetIdProcess(const QByteArray &name)
{
    if (name.startsWith("LC_"))
        return true;
    for (const char *kept : KeptVariables) {
        if (name == kept)
            return true;
    }
    return false;
}

bool prepareSetIdProcess(QList<QByteArray> *removed)
{
    QList<QByteArray> names;
    for (char **entry = environ; entry && *entry; ++entry) {
        const QByteArray variable(*entry);
        const QByteArray name = variable.left(variable.indexOf('='));
        if (!keptInSetIdProcess(name))
            names << name;
    }
    for (const QByteArray &name : names)
        ::unsetenv(name.constData());
    if (removed)
        *removed = names;

    struct rlimit core {};
    if (::getrlimit(RLIMIT_CORE, &core) == 0) {
        core.rlim_cur = 0;
        ::setrlimit(RLIMIT_CORE, &core);
    }

    // libaccounts cannot open the database without the session bus, which
    // GLib looks for below XDG_RUNTIME_DIR when it ignores
    // DBUS_SESSION_BUS_ADDRESS in a set-id process.
    if (const QByteArray runtimeDir = QByteArray(RuntimeRoot) + '/' + QByteArray::number(::getuid());
        !qEnvironmentVariableIsSet("XDG_RUNTIME_DIR") && ownedDirectory(runtimeDir, ::getuid()))
        ::setenv("XDG_RUNTIME_DIR", runtimeDir.constData(), 1);

    const struct passwd *user = ::getpwuid(::getuid());
    if (!user || !user->pw_dir || user->pw_dir[0] != '/')
        return false;
    return ::setenv("HOME", user->pw_dir, 1) == 0;
}

} // namespace NetVfs::Bridge
