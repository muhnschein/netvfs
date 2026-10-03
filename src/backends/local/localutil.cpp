// SPDX-License-Identifier: LGPL-2.1-or-later
#include "localutil.h"
#include "names.h"

#include <QtCore/QElapsedTimer>

#include <cerrno>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

Q_LOGGING_CATEGORY(lcNetVfsLocal, "netvfs.local", QtWarningMsg)

namespace NetVfs::Local {

namespace {

constexpr int PollSliceMs = 100;              // C-9: cancel is seen within one slice
constexpr size_t InitialNameBuffer = 1024;
constexpr size_t MaxNameBuffer = 1 << 20;
constexpr qint64 MsecsPerSec = 1000;
constexpr qint64 NsecsPerMsec = 1000000;

EntryType typeFromMode(mode_t mode)
{
    switch (mode & S_IFMT) {
    case S_IFREG:
        return EntryType::File;
    case S_IFDIR:
        return EntryType::Directory;
    case S_IFLNK:
        return EntryType::Symlink;
    default:
        return EntryType::Special;   // FIFO, socket, device
    }
}

qint64 toMsecs(qint64 seconds, qint64 nanoseconds)
{
    return seconds * MsecsPerSec + nanoseconds / NsecsPerMsec;
}

void fromStat(const struct stat &st, NativeStat *out)
{
    out->type = typeFromMode(st.st_mode);
    out->size = st.st_size;
    out->mode = static_cast<qint32>(st.st_mode & 07777);
    out->uid = st.st_uid;
    out->gid = st.st_gid;
    out->modifiedMs = toMsecs(st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
    out->accessedMs = toMsecs(st.st_atim.tv_sec, st.st_atim.tv_nsec);
    out->hasBirth = false;
    out->device = st.st_dev;
    out->inode = st.st_ino;
}

int fstatatFallback(int dirFd, const char *path, int flags, NativeStat *out)
{
    struct stat st {};
    if (::fstatat(dirFd, path, &st, flags) != 0)
        return errno;
    fromStat(st, out);
    return 0;
}

#ifdef STATX_BTIME
// statx() is missing on old kernels (ENOSYS) and blocked by some seccomp
// profiles (EPERM on a path that exists); fstatat() is used from then on.
std::atomic<bool> &statxUsable()
{
    static std::atomic<bool> usable { true };
    return usable;
}

void fromStatx(const struct statx &stx, NativeStat *out)
{
    out->type = typeFromMode(stx.stx_mode);
    out->size = static_cast<qint64>(stx.stx_size);
    out->mode = static_cast<qint32>(stx.stx_mode & 07777);
    out->uid = stx.stx_uid;
    out->gid = stx.stx_gid;
    out->modifiedMs = toMsecs(stx.stx_mtime.tv_sec, stx.stx_mtime.tv_nsec);
    out->accessedMs = toMsecs(stx.stx_atime.tv_sec, stx.stx_atime.tv_nsec);
    out->hasBirth = (stx.stx_mask & STATX_BTIME) != 0;
    out->birthMs = out->hasBirth ? toMsecs(stx.stx_btime.tv_sec, stx.stx_btime.tv_nsec) : 0;
    out->device = makedev(stx.stx_dev_major, stx.stx_dev_minor);
    out->inode = stx.stx_ino;
}

int statxAt(int dirFd, const char *path, int flags, NativeStat *out)
{
    if (statxUsable()) {
        if (struct statx stx {};
                ::statx(dirFd, path, flags | AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS | STATX_BTIME, &stx) == 0) {
            fromStatx(stx, out);
            return 0;
        }
        if (errno != ENOSYS && errno != EPERM)
            return errno;
        statxUsable() = false;
    }
    return fstatatFallback(dirFd, path, flags, out);
}
#else
int statxAt(int dirFd, const char *path, int flags, NativeStat *out)
{
    return fstatatFallback(dirFd, path, flags, out);
}
#endif

// getpwuid_r/getgrgid_r with a growing buffer. `lookup` returns the name or
// an empty string; ERANGE asks for a larger buffer.
template<typename Lookup>
QString lookupName(Lookup lookup)
{
    size_t size = InitialNameBuffer;
    while (size <= MaxNameBuffer) {
        std::vector<char> buffer(size);
        QString name;
        if (const int rc = lookup(buffer.data(), buffer.size(), &name); rc != ERANGE)
            return rc == 0 ? name : QString();
        size *= 2;
    }
    return QString();
}

} // namespace

void Fd::reset(int fd)
{
    if (m_fd >= 0)
        ::close(m_fd);
    m_fd = fd;
}

int Fd::close()
{
    if (m_fd < 0)
        return 0;
    const int rc = ::close(m_fd);
    m_fd = -1;
    // Linux releases the descriptor even when close() reports EINTR.
    return rc == 0 || errno == EINTR ? 0 : errno;
}

int statAt(int dirFd, const QByteArray &path, bool follow, NativeStat *out)
{
    return statxAt(dirFd, path.constData(), follow ? 0 : AT_SYMLINK_NOFOLLOW, out);
}

int statFd(int fd, NativeStat *out)
{
    return statxAt(fd, "", AT_EMPTY_PATH, out);
}

Error errorFor(int error)
{
    switch (error) {
    case 0:
        return Error::None;
    case ENOENT:
    case ELOOP:
    case ESTALE:
        return Error::NotFound;
    case EEXIST:
        return Error::AlreadyExists;
    case EACCES:
    case EPERM:
        return Error::PermissionDenied;
    case ENOTDIR:
        return Error::NotADirectory;
    case EISDIR:
        return Error::IsADirectory;
    case ENOTEMPTY:
        return Error::DirectoryNotEmpty;
    case EROFS:
        return Error::ReadOnlyFilesystem;
    case ENOSPC:
    case EDQUOT:
    case EFBIG:
        return Error::NoSpace;
    case ENAMETOOLONG:
    case EILSEQ:
        return Error::InvalidName;
    case EBUSY:
    case ETXTBSY:
        return Error::Locked;
    case EXDEV:
    case ENOSYS:
    case EOPNOTSUPP:
    case ENXIO:
    case ENODEV:
        return Error::Unsupported;
    case ETIMEDOUT:
        return Error::Timeout;
    case ENOTCONN:
        return Error::ConnectionLost;
    default:
        return Error::Internal;
    }
}

Result errnoResult(int error, const QString &context)
{
    return Result(errorFor(error), QStringLiteral("%1: %2").arg(context, QString::fromLocal8Bit(std::strerror(error))),
                  QStringLiteral("errno %1").arg(error));
}

QString display(const QByteArray &native)
{
    return Names::display(Names::decode(native));
}

QDateTime fromMsecs(qint64 ms)
{
    return QDateTime::fromMSecsSinceEpoch(ms, Qt::UTC);
}

struct timespec toTimespec(const QDateTime &time)
{
    struct timespec ts {};
    if (!time.isValid()) {
        ts.tv_nsec = UTIME_OMIT;
        return ts;
    }
    const qint64 ms = time.toMSecsSinceEpoch();
    qint64 seconds = ms / MsecsPerSec;
    qint64 rest = ms % MsecsPerSec;
    if (rest < 0) {
        rest += MsecsPerSec;
        --seconds;
    }
    ts.tv_sec = static_cast<time_t>(seconds);
    ts.tv_nsec = static_cast<long>(rest * NsecsPerMsec);
    return ts;
}

QByteArray parentOf(const QByteArray &native)
{
    const int slash = native.lastIndexOf('/');
    return slash <= 0 ? QByteArray("/") : native.left(slash);
}

void syncFolder(const QByteArray &native)
{
    if (const Fd folder(::open(native.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            folder.valid() && ::fsync(folder.get()) != 0)
        qCDebug(lcNetVfsLocal) << "fsync of a folder failed:" << std::strerror(errno);
}

QString AccountNames::user(qint64 uid)
{
    if (const auto cached = m_users.constFind(uid); cached != m_users.constEnd())
        return *cached;
    const QString name = lookupName([uid](char *buffer, size_t size, QString *out) {
        struct passwd pwd {};
        struct passwd *found = nullptr;
        const int rc = ::getpwuid_r(static_cast<uid_t>(uid), &pwd, buffer, size, &found);
        if (rc == 0 && found)
            *out = QString::fromLocal8Bit(found->pw_name);
        return rc;
    });
    m_users.insert(uid, name);
    return name;
}

QString AccountNames::group(qint64 gid)
{
    if (const auto cached = m_groups.constFind(gid); cached != m_groups.constEnd())
        return *cached;
    const QString name = lookupName([gid](char *buffer, size_t size, QString *out) {
        struct group grp {};
        struct group *found = nullptr;
        const int rc = ::getgrgid_r(static_cast<gid_t>(gid), &grp, buffer, size, &found);
        if (rc == 0 && found)
            *out = QString::fromLocal8Bit(found->gr_name);
        return rc;
    });
    m_groups.insert(gid, name);
    return name;
}

void AccountNames::clear()
{
    m_users.clear();
    m_groups.clear();
}

Result Waiter::check() const
{
    return canceled() ? Result(Error::Canceled) : Result::success();
}

Result Waiter::wait(int fd, short events) const
{
    QElapsedTimer timer;
    timer.start();
    for (;;) {
        if (canceled())
            return Result(Error::Canceled);
        if (m_timeoutMs > 0 && timer.elapsed() >= m_timeoutMs)
            return Result(Error::Timeout, QStringLiteral("No data within %1 ms").arg(m_timeoutMs));
        struct pollfd pfd {};
        pfd.fd = fd;
        pfd.events = events;
        const int rc = ::poll(&pfd, 1, PollSliceMs);
        if (rc > 0)
            return Result::success();   // ready, or an error the next call reports
        if (rc < 0 && errno != EINTR)
            return errnoResult(errno, QStringLiteral("poll"));
    }
}

Result readOnce(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got)
{
    for (;;) {
        if (const ssize_t n = offset >= 0 ? ::pread(fd, buffer, static_cast<size_t>(length), offset)
                                          : ::read(fd, buffer, static_cast<size_t>(length));
                n >= 0) {
            *got = n;
            return Result::success();
        }
        if (errno == EAGAIN) {
            if (const Result r = waiter.wait(fd, POLLIN); !r.ok())
                return r;
        } else if (errno != EINTR) {
            return errnoResult(errno, QStringLiteral("Cannot read"));
        }
    }
}

Result readFully(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got)
{
    qint64 done = 0;
    while (done < length) {
        if (const Result r = waiter.check(); !r.ok())   // L-6
            return r;
        qint64 n = 0;
        const qint64 position = offset >= 0 ? offset + done : -1;
        if (const Result r = readOnce(fd, position, buffer + done, qMin(ChunkSize, length - done), waiter, &n);
                !r.ok())
            return r;
        if (n == 0)
            break;
        done += n;
    }
    *got = done;
    return Result::success();
}

Result writeFully(int fd, const char *data, qint64 length, const Waiter &waiter)
{
    qint64 done = 0;
    while (done < length) {
        if (const Result r = waiter.check(); !r.ok())   // L-6
            return r;
        if (const ssize_t n = ::write(fd, data + done, static_cast<size_t>(qMin(ChunkSize, length - done))); n >= 0) {
            done += n;
        } else if (errno == EAGAIN) {
            if (const Result r = waiter.wait(fd, POLLOUT); !r.ok())
                return r;
        } else if (errno != EINTR) {
            return errnoResult(errno, QStringLiteral("Cannot write"));
        }
    }
    return Result::success();
}

} // namespace NetVfs::Local
