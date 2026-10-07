// SPDX-License-Identifier: LGPL-2.1-or-later
#include "privileges.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <vector>

#include <pwd.h>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace NetVfs::Bridge {

namespace {

const char RuntimeRoot[] = "/run/user";

constexpr std::array<const char *, 5> KeptVariables {
    "LANG", "LANGUAGE", "TZ", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
};
// getpwuid_r's buffer when sysconf has no suggestion.
constexpr long DefaultPasswdBufferSize = 16384;

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
    return name.startsWith("LC_")
        || std::any_of(KeptVariables.begin(), KeptVariables.end(),
                       [&name](const char *kept) { return name == kept; });
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

    if (struct rlimit core {}; ::getrlimit(RLIMIT_CORE, &core) == 0) {
        core.rlim_cur = 0;
        ::setrlimit(RLIMIT_CORE, &core);
    }

    // libaccounts cannot open the database without the session bus, which
    // GLib looks for below XDG_RUNTIME_DIR when it ignores
    // DBUS_SESSION_BUS_ADDRESS in a set-id process.
    if (const QByteArray runtimeDir = QByteArray(RuntimeRoot) + '/' + QByteArray::number(::getuid());
        !qEnvironmentVariableIsSet("XDG_RUNTIME_DIR") && ownedDirectory(runtimeDir, ::getuid()))
        ::setenv("XDG_RUNTIME_DIR", runtimeDir.constData(), 1);

    const long suggested = ::sysconf(_SC_GETPW_R_SIZE_MAX);
    std::vector<char> buffer(static_cast<size_t>(suggested > 0 ? suggested : DefaultPasswdBufferSize));
    struct passwd entry {};
    struct passwd *user = nullptr;
    if (::getpwuid_r(::getuid(), &entry, buffer.data(), buffer.size(), &user) != 0 || !user || !user->pw_dir
            || user->pw_dir[0] != '/')
        return false;
    return ::setenv("HOME", user->pw_dir, 1) == 0;
}

} // namespace NetVfs::Bridge
