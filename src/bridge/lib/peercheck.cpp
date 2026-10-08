// SPDX-License-Identifier: LGPL-2.1-or-later
#include "peercheck.h"

#include <QtCore/QFile>

#include <cerrno>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77   // Linux 6.5
#endif

namespace NetVfs::Bridge {

namespace {

constexpr int StartTimeField = 22;          // proc(5): starttime, clock ticks since boot
constexpr qint64 MaxProcFileBytes = 4096;
constexpr size_t CompareChunkBytes = 64 * 1024;

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
    // "<seconds>.<centiseconds> ...", parsed as integers: as a double, 0.29 *
    // 100 truncates to 28, a tick before the start time of a peer that
    // started in that tick, which was then refused as a reused pid.
    const QByteArray uptime = readSmallFile(QStringLiteral("/proc/uptime"));
    const QByteArray field = uptime.left(uptime.indexOf(' '));
    const int dot = field.indexOf('.');
    // The fraction as nanoseconds: padded or cut to nine digits.
    const QByteArray fraction = (dot < 0 ? QByteArray() : field.mid(dot + 1)).leftJustified(9, '0', true);
    bool secondsOk = false;
    bool fractionOk = false;
    const qint64 seconds = (dot < 0 ? field : field.left(dot)).toLongLong(&secondsOk);
    const qint64 nanoseconds = fraction.toLongLong(&fractionOk);
    if (!secondsOk || !fractionOk || seconds < 0 || nanoseconds < 0)
        return -1;
    const qint64 hz = ::sysconf(_SC_CLK_TCK);
    return seconds * hz + nanoseconds * hz / 1000000000;
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

// Reads up to `size` bytes; fewer only at the end of the file. -1 on error.
ssize_t readFully(int fd, char *buffer, size_t size)
{
    size_t done = 0;
    while (done < size) {
        const ssize_t n = ::read(fd, buffer + done, size - done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return -1;
        if (n == 0)
            break;
        done += static_cast<size_t>(n);
    }
    return static_cast<ssize_t>(done);
}

// Byte for byte, in chunks (bounded memory), from the current offsets.
bool sameContent(int a, int b)
{
    std::vector<char> left(CompareChunkBytes);
    std::vector<char> right(CompareChunkBytes);
    for (;;) {
        const ssize_t n = readFully(a, left.data(), left.size());
        if (n < 0 || readFully(b, right.data(), right.size()) != n
                || std::memcmp(left.data(), right.data(), static_cast<size_t>(n)) != 0)
            return false;
        if (n == 0)
            return true;
    }
}

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
    if (socklen_t length = sizeof(cred);
        ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0 || length != sizeof(cred))
        return false;
    out->pid = cred.pid;
    out->uid = cred.uid;
    int pidfd = -1;
    if (socklen_t pidfdLength = sizeof(pidfd);
        ::getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfdLength) == 0 && pidfd >= 0)
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
    if (const qint64 now = m_env.bootTicksNow(); now >= 0 && before > now)
        return refused(QStringLiteral("peer pid %1 was reused").arg(pid));

    // Opened, not only stat()ed, inside the start time window: the open file
    // stays the one this process runs, and its content is compared from it.
    const QByteArray exePath = QFile::encodeName(procPath(pid, "exe"));
    const int exeFd = ::open(exePath.constData(), O_RDONLY | O_CLOEXEC);
    const FdCloser exeCloser(exeFd);
    struct stat exe {};
    const bool haveExe = exeFd >= 0 && ::fstat(exeFd, &exe) == 0;
    if (m_env.afterExeRead)
        m_env.afterExeRead();

    if (qint64 after = 0; !startTime(pid, &after) || after != before)
        return refused(QStringLiteral("peer pid %1 was reused").arg(pid));
    if (pidfd >= 0 && !pidfdAlive(pidfd, pid))
        return refused(QStringLiteral("peer process %1 exited during the check").arg(pid));
    if (!haveExe)
        return refused(QStringLiteral("cannot read the executable of peer %1").arg(pid));

    const QByteArray expectedPath = QFile::encodeName(m_executable);
    const int expectedFd = ::open(expectedPath.constData(), O_RDONLY | O_CLOEXEC);
    const FdCloser expectedCloser(expectedFd);
    struct stat expected {};
    if (expectedFd < 0 || ::fstat(expectedFd, &expected) != 0)
        return refused(QStringLiteral("the registered executable cannot be read"));
    if (exe.st_dev == expected.st_dev && exe.st_ino == expected.st_ino)
        return Result::success();
    // Sailjail's firejail --private-bin runs a copy of the executable from a
    // tmpfs: another file, so the same bytes are required instead.
    if (exe.st_size != expected.st_size || !sameContent(exeFd, expectedFd))
        return refused(QStringLiteral("peer %1 runs another executable").arg(pid));
    return Result::success();
}

} // namespace NetVfs::Bridge
