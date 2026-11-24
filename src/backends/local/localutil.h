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
constexpr qint64 ChunkSize = 1 << 20;

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
    int close();

private:
    int m_fd = -1;
};

struct NativeStat {
    EntryType type = EntryType::Unknown;
    qint64 size = 0;
    qint32 mode = 0;
    qint64 uid = -1;
    qint64 gid = -1;
    qint64 modifiedMs = 0;
    qint64 accessedMs = 0;
    qint64 birthMs = 0;
    bool hasBirth = false;
    quint64 device = 0;
    quint64 inode = 0;

    bool isDir() const { return type == EntryType::Directory; }
    bool sameFile(const NativeStat &other) const
    {
        return device == other.device && inode == other.inode;
    }
};

int statAt(int dirFd, const QByteArray &path, bool follow, NativeStat *out);
int statFd(int fd, NativeStat *out);

Error errorFor(int error);
Result errnoResult(int error, const QString &context);

QString display(const QByteArray &native);
QDateTime fromMsecs(qint64 ms);
struct timespec toTimespec(const QDateTime &time);
QByteArray parentOf(const QByteArray &native);
void syncFolder(const QByteArray &native);

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

class Waiter
{
public:
    Waiter(const std::atomic<bool> *canceled, int timeoutMs) : m_canceled(canceled), m_timeoutMs(timeoutMs) {}

    bool canceled() const { return m_canceled->load(); }
    Result check() const;
    Result wait(int fd, short events) const;

private:
    const std::atomic<bool> *m_canceled;
    int m_timeoutMs;
};

Result readOnce(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got);
Result readFully(int fd, qint64 offset, char *buffer, qint64 length, const Waiter &waiter, qint64 *got);
Result writeFully(int fd, const char *data, qint64 length, const Waiter &waiter);

}
#endif
