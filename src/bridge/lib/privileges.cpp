// SPDX-License-Identifier: LGPL-2.1-or-later
#include "privileges.h"

#include "bridgelog.h"

#include <QtCore/QFile>
#include <QtDBus/QDBusError>

#include <cstdlib>

#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace NetVfs::Bridge {

namespace {

const char RuntimeRoot[] = "/run/user";
const char SessionBusName[] = "netvfs-bridge-session";

const char *const KeptVariables[] = {
    "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ",
    "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET", "JOURNAL_STREAM", "INVOCATION_ID",
    "QT_LOGGING_RULES",
};

bool ownedBy(const QByteArray &path, uid_t uid, mode_t type)
{
    struct stat st {};
    return ::lstat(path.constData(), &st) == 0 && st.st_uid == uid && (st.st_mode & S_IFMT) == type;
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

QList<QByteArray> prepareSetIdProcess()
{
    QList<QByteArray> removed;
    for (char **entry = environ; entry && *entry; ++entry) {
        const QByteArray variable(*entry);
        const QByteArray name = variable.left(variable.indexOf('='));
        if (!keptInSetIdProcess(name))
            removed << name;
    }
    for (const QByteArray &name : removed)
        ::unsetenv(name.constData());

    if (const QByteArray runtimeDir = QByteArray(RuntimeRoot) + '/' + QByteArray::number(::getuid());
        !qEnvironmentVariableIsSet("XDG_RUNTIME_DIR") && ownedBy(runtimeDir, ::getuid(), S_IFDIR))
        ::setenv("XDG_RUNTIME_DIR", runtimeDir.constData(), 1);

    // Dumpable again, but no core file: one would be written as the user and
    // carry memory the `privileged` group protects (account settings).
    struct rlimit core {};
    if (::getrlimit(RLIMIT_CORE, &core) == 0) {
        core.rlim_cur = 0;
        ::setrlimit(RLIMIT_CORE, &core);
    }
    ::prctl(PR_SET_DUMPABLE, 1);
    return removed;
}

QString userBusAddress(const QString &runtimeRoot, uid_t uid)
{
    const QString path = runtimeRoot + QLatin1Char('/') + QString::number(uid) + QStringLiteral("/bus");
    if (!ownedBy(QFile::encodeName(path), uid, S_IFSOCK))
        return QString();
    return QStringLiteral("unix:path=") + path;
}

QDBusConnection sessionBus()
{
    if (QDBusConnection bus = QDBusConnection::sessionBus(); bus.isConnected())
        return bus;
    const QString name = QLatin1String(SessionBusName);
    if (QDBusConnection bus(name); bus.isConnected())
        return bus;
    const QString address = userBusAddress(QLatin1String(RuntimeRoot), ::getuid());
    if (address.isEmpty()) {
        qCWarning(lcNetVfsBridge) << "No session bus: notifications and the settings handoff do not work";
        return QDBusConnection::sessionBus();
    }
    qCDebug(lcNetVfsBridge) << "libdbus found no session bus, connecting to" << address;
    QDBusConnection bus = QDBusConnection::connectToBus(address, name);
    if (!bus.isConnected()) {
        qCWarning(lcNetVfsBridge) << "Cannot connect to the session bus:" << bus.lastError().message();
        QDBusConnection::disconnectFromBus(name);   // the next call tries again
    }
    return bus;
}

} // namespace NetVfs::Bridge
