// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOCALUTIL_H
#define NETVFS_LOCALUTIL_H

#include "error.h"
#include "types.h"

#include <QtCore/QHash>
#include <QtCore/QLoggingCategory>

#include <atomic>

#include <time.h>

Q_DECLARE_LOGGING_CATEGORY(lcNetVfsLocal)

namespace NetVfs::Local {

// SPEC-v2 L-6: the unit in which reads, writes, copies and checksums check
// cancel() (C-9) and in which memory is bounded (C-10).
constexpr qint64 ChunkSize = 1 << 20;

// Owns one file descriptor.
class Fd
{
public:
    Fd() = default;
    explicit Fd(int fd) : m_fd(fd) {}
    Fd(Fd &&other) noexcept : m_fd(other.release()) {}
    Fd &operator=(Fd &&other) noexcept
    {
        reset(other.release());
        return *this;
    }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    ~Fd() { reset(); }

    int get() const { return m_fd; }
    bool valid() const { return m_fd >= 0; }
    int release()
    {
        const int fd = m_fd;
        m_fd = -1;
        return fd;
    }
    void reset(int fd = -1);
    // close(2) result; 0 or an errno value. The descriptor is gone either way.
    int close();

private:
    int m_fd = -1;
};

// The parts of statx()/stat() the backend uses.
struct NativeStat {
    EntryType type = EntryType::Unknown;
    qint64 size = 0;
    qint32 mode = 0;               // permission bits & 07777
    qint64 uid = -1;
    qint64 gid = -1;
    qint64 modifiedMs = 0;
    qint64 accessedMs = 0;
    qint64 birthMs = 0;
    bool hasBirth = false;         // statx STATX_BTIME (L-2)
    quint64 device = 0;
    quint64 inode = 0;

    bool isDir() const { return type == EntryType::Directory; }
    bool sameFile(const NativeStat &other) const
    {
        return device == other.device && inode == other.inode;
    }
};

// statx() relative to `dirFd` (AT_FDCWD for absolute paths), falling back to
// fstatat() where the kernel or C library lacks statx (L-2). `follow` false:
// lstat semantics. Returns 0 or an errno value.
int statAt(int dirFd, const QByteArray &path, bool follow, NativeStat *out);
int statFd(int fd, NativeStat *out);

// Maps an errno value to the error taxonomy (SPEC 5.4, XC-21).
Error errorFor(int error);
Result errnoResult(int error, const QString &context);

QString display(const QByteArray &native);
QDateTime fromMsecs(qint64 ms);
// utimensat()/futimens() value; an invalid time leaves the field alone.
struct timespec toTimespec(const QDateTime &time);
// Folder part of a native path ("/" for top-level entries).
QByteArray parentOf(const QByteArray &native);
// fsync() of a folder, best effort (L-7).
void syncFolder(const QByteArray &native);

// Names for uid/gid values (getpwuid_r/getgrgid_r), cached per connection.
class AccountNames
{
public:
    QString user(qint64 uid);
    QString group(qint64 gid);
    void clear();

private:
    QHash<qint64, QString> m_users;
    QHash<qint64, QString> m_groups;
};

// C-9 and C-14 for descriptors that can block (FIFOs, sockets, devices):
// waits in slices so that cancel() is seen within one slice.
class Waiter
{
public:
    Waiter(const std::atomic<bool> *canceled, int timeoutMs) : m_canceled(canceled), m_timeoutMs(timeoutMs) {}

    bool canceled() const { return m_canceled->load(); }
    Result check() const;
    // Waits until `fd` is ready for `events` (POLLIN/POLLOUT).
    Result wait(int fd, short events) const;

private:
    const std::atomic<bool> *m_canceled;
    int m_timeoutMs;
};

// One read: pread() at `offset`, or read() from the current position when
// `offset` < 0 (streams). Waits for streams that have no data yet. `*got` is
// 0 at end of file.
Result readOnce(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got);
// Reads until `length` bytes or end of file, checking cancel between chunks.
Result readFully(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got);
// Writes everything at the current position, checking cancel between chunks.
Result writeFully(int fd, const char *data, qint64 length, const Waiter &waiter);

} // namespace NetVfs::Local

#endif
