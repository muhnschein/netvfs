// SPDX-License-Identifier: LGPL-2.1-or-later
#include "peercheck.h"

#include <QtCore/QFile>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77   // Linux 6.5
#endif

namespace NetVfs {
namespace Bridge {

namespace {

constexpr int StartTimeField = 22;          // proc(5): starttime, clock ticks since boot
constexpr qint64 MaxProcFileBytes = 4096;

Result refused(const QString &why)
{
    return Result(Error::PermissionDenied, why);
}

QByteArray readSmallFile(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QByteArray();
    return file.read(MaxProcFileBytes);
}

int defaultOpenPidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#else
    Q_UNUSED(pid)
    return -1;
#endif
}

qint64 defaultBootTicksNow()
{
    const QByteArray uptime = readSmallFile(QStringLiteral("/proc/uptime"));
    bool ok = false;
    const double seconds = uptime.left(uptime.indexOf(' ')).toDouble(&ok);
    if (!ok)
        return -1;
    return static_cast<qint64>(seconds * static_cast<double>(::sysconf(_SC_CLK_TCK)));
}

class FdCloser
{
public:
    explicit FdCloser(int fd) : m_fd(fd) {}
    ~FdCloser()
    {
        if (m_fd >= 0)
            ::close(m_fd);
    }
    FdCloser(const FdCloser &) = delete;
    FdCloser &operator=(const FdCloser &) = delete;

private:
    int m_fd;
};

} // namespace

PeerChecker::PeerChecker(const QString &executable)
    : PeerChecker(executable, Environment())
{
}

PeerChecker::PeerChecker(const QString &executable, const Environment &environment)
    : m_executable(executable)
    , m_env(environment)
{
    if (!m_env.credentials)
        m_env.credentials = systemCredentials;
    if (!m_env.openPidfd)
        m_env.openPidfd = defaultOpenPidfd;
    if (!m_env.bootTicksNow)
        m_env.bootTicksNow = defaultBootTicksNow;
    if (m_env.ownUid == 0)
        m_env.ownUid = ::geteuid();
}

bool PeerChecker::systemCredentials(int fd, PeerCredentials *out)
{
    struct ucred cred {};
    socklen_t length = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0 || length != sizeof(cred))
        return false;
    out->pid = cred.pid;
    out->uid = cred.uid;
    int pidfd = -1;
    socklen_t pidfdLength = sizeof(pidfd);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfdLength) == 0 && pidfd >= 0)
        out->pidfd = pidfd;
    return true;
}

Result PeerChecker::check(int socketFd) const
{
    PeerCredentials credentials;
    if (socketFd < 0 || !m_env.credentials(socketFd, &credentials))
        return refused(QStringLiteral("no peer credentials"));
    const FdCloser closer(credentials.pidfd);
    return checkCredentials(credentials);
}

Result PeerChecker::checkCredentials(const PeerCredentials &credentials) const
{
    if (credentials.uid != m_env.ownUid)
        return refused(QStringLiteral("peer uid %1 is not the bridge's uid").arg(credentials.uid));
    if (credentials.pid <= 0)
        return refused(QStringLiteral("no peer process"));
    if (credentials.pidfd >= 0)
        return checkProcess(credentials.pid, credentials.pidfd);
    const int pidfd = m_env.openPidfd(credentials.pid);
    const FdCloser closer(pidfd);
    return checkProcess(credentials.pid, pidfd);
}

QString PeerChecker::procPath(pid_t pid, const char *leaf) const
{
    return m_env.procRoot + QLatin1Char('/') + QString::number(pid) + QLatin1Char('/') + QLatin1String(leaf);
}

bool PeerChecker::startTime(pid_t pid, qint64 *ticks) const
{
    const QByteArray stat = readSmallFile(procPath(pid, "stat"));
    // "pid (comm) state ..." where comm may contain spaces and parentheses.
    const int close = stat.lastIndexOf(')');
    if (close < 0)
        return false;
    const QList<QByteArray> fields = stat.mid(close + 2).split(' ');
    // fields[0] is field 3 (state).
    const int index = StartTimeField - 3;
    if (fields.size() <= index)
        return false;
    bool ok = false;
    *ticks = fields.at(index).toLongLong(&ok);
    return ok;
}

bool PeerChecker::pidfdAlive(int pidfd, pid_t pid) const
{
    const QByteArray info = readSmallFile(m_env.procRoot + QStringLiteral("/self/fdinfo/") + QString::number(pidfd));
    for (const QByteArray &line : info.split('\n')) {
        if (line.startsWith("Pid:"))
            return line.mid(4).trimmed().toLongLong() == pid;
    }
    return false;
}

Result PeerChecker::checkProcess(pid_t pid, int pidfd) const
{
    qint64 before = 0;
    if (!startTime(pid, &before))
        return refused(QStringLiteral("peer process %1 is gone").arg(pid));
    const qint64 now = m_env.bootTicksNow();
    if (now >= 0 && before > now)
        return refused(QStringLiteral("peer pid %1 was reused").arg(pid));

    struct stat exe {};
    const QByteArray exePath = QFile::encodeName(procPath(pid, "exe"));
    const bool haveExe = ::stat(exePath.constData(), &exe) == 0;
    if (m_env.afterExeRead)
        m_env.afterExeRead();

    qint64 after = 0;
    if (!startTime(pid, &after) || after != before)
        return refused(QStringLiteral("peer pid %1 was reused").arg(pid));
    if (pidfd >= 0 && !pidfdAlive(pidfd, pid))
        return refused(QStringLiteral("peer process %1 exited during the check").arg(pid));
    if (!haveExe)
        return refused(QStringLiteral("cannot read the executable of peer %1").arg(pid));

    struct stat expected {};
    const QByteArray expectedPath = QFile::encodeName(m_executable);
    if (::stat(expectedPath.constData(), &expected) != 0)
        return refused(QStringLiteral("the registered executable does not exist"));
    if (exe.st_dev != expected.st_dev || exe.st_ino != expected.st_ino)
        return refused(QStringLiteral("peer %1 runs another executable").arg(pid));
    return Result::success();
}

} // namespace Bridge
} // namespace NetVfs
