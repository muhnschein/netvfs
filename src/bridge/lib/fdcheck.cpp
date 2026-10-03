// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fdcheck.h"

#include <algorithm>
#include <cerrno>
#include <climits>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace NetVfs::Bridge {

namespace {

constexpr int PollSliceMs = 200;

Result denied(const QString &why)
{
    return Result(Error::PermissionDenied, why);
}

bool accessModeAllows(int flags, FdAccess need)
{
    const int mode = flags & O_ACCMODE;
    if (need == FdAccess::Read)
        return mode == O_RDONLY || mode == O_RDWR;
    return mode == O_WRONLY || mode == O_RDWR;
}

} // namespace

Result checkTransferFd(int fd, FdAccess need, FdInfo *info)
{
    if (fd < 0)
        return denied(QStringLiteral("No file descriptor"));
    struct stat st {};
    if (::fstat(fd, &st) != 0)
        return denied(QStringLiteral("Invalid file descriptor"));
    const bool regular = S_ISREG(st.st_mode);
    const bool fifo = S_ISFIFO(st.st_mode);
    if (!regular && !fifo)
        return denied(QStringLiteral("Only regular files and pipes can be transferred"));
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0)
        return denied(QStringLiteral("Invalid file descriptor"));
#ifdef O_PATH
    if (flags & O_PATH)
        return denied(QStringLiteral("The file descriptor was opened without access"));
#endif
    if (!accessModeAllows(flags, need)) {
        return denied(need == FdAccess::Read ? QStringLiteral("The file is not open for reading")
                                             : QStringLiteral("The file is not open for writing"));
    }
    if (need == FdAccess::Write && regular && (flags & O_APPEND))
        return denied(QStringLiteral("The file is open for appending"));
    if (info) {
        info->fifo = fifo;
        info->size = regular ? static_cast<qint64>(st.st_size) : -1;
    }
    return Result::success();
}

Result checkUploadLength(const FdInfo &info, qint64 size, const QString &provider)
{
    if (info.fifo && size < 0 && provider == QLatin1String("webdav"))
        return Result(Error::Unsupported, QStringLiteral("Uploading from a pipe to this location needs opts.size"));
    return Result::success();
}

FdDevice::FdDevice(int fd, const FdInfo &info, qint64 offset, qint64 length, const std::atomic<bool> *canceled)
    : m_fd(fd)
    , m_info(info)
    , m_offset(offset)
    , m_length(length)
    , m_canceled(canceled)
{
}

FdDevice::~FdDevice()
{
    close();
}

bool FdDevice::isSequential() const
{
    return m_info.fifo;
}

qint64 FdDevice::size() const
{
    if (m_length >= 0)
        return m_length;
    if (m_info.fifo)
        return 0;
    struct stat st {};
    if (m_fd < 0 || ::fstat(m_fd, &st) != 0)
        return 0;
    return std::max<qint64>(0, static_cast<qint64>(st.st_size) - m_offset);
}

bool FdDevice::seek(qint64 pos)
{
    if (m_info.fifo || pos < 0)
        return false;
    return QIODevice::seek(pos);
}

void FdDevice::close()
{
    m_fd = -1;           // not owned: the job's UnixFd closes it when the job ends (XB-11)
    if (isOpen())
        QIODevice::close();
}

bool FdDevice::waitFor(short events) const
{
    for (;;) {
        if (canceled())
            return false;
        struct pollfd p { m_fd, events, 0 };
        const int rc = ::poll(&p, 1, PollSliceMs);
        if (rc > 0)
            return true;
        if (rc < 0 && errno != EINTR)
            return false;
    }
}

qint64 FdDevice::readData(char *data, qint64 maxSize)
{
    if (m_fd < 0 || canceled())
        return -1;
    qint64 want = maxSize;
    const qint64 position = m_info.fifo ? m_streamPos : pos();
    if (m_length >= 0)
        want = std::min(want, m_length - position);
    if (want <= 0)
        return 0;
    want = std::min<qint64>(want, INT_MAX);
    ssize_t n = 0;
    if (m_info.fifo) {
        if (!waitFor(POLLIN))
            return -1;
        do {
            n = ::read(m_fd, data, static_cast<size_t>(want));
        } while (n < 0 && errno == EINTR);
    } else {
        do {
            n = ::pread(m_fd, data, static_cast<size_t>(want), static_cast<off_t>(m_offset + position));
        } while (n < 0 && errno == EINTR);
    }
    if (n < 0)
        return -1;
    m_streamPos += n;
    m_transferred += n;
    return n;
}

qint64 FdDevice::writeData(const char *data, qint64 maxSize)
{
    if (m_fd < 0 || canceled())
        return -1;
    if (m_info.fifo) {
        // At most PIPE_BUF per poll so a write never blocks beyond the slice.
        if (!waitFor(POLLOUT))
            return -1;
        const auto chunk = static_cast<size_t>(std::min<qint64>(maxSize, PIPE_BUF));
        ssize_t n = 0;
        do {
            n = ::write(m_fd, data, chunk);
        } while (n < 0 && errno == EINTR);
        if (n < 0)
            return -1;
        m_streamPos += n;
        m_transferred += n;
        return n;
    }
    qint64 written = 0;
    while (written < maxSize) {
        const auto chunk = static_cast<size_t>(std::min<qint64>(maxSize - written, INT_MAX));
        const ssize_t n = ::pwrite(m_fd, data + written, chunk, static_cast<off_t>(m_offset + pos() + written));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return written > 0 ? written : -1;
        written += n;
    }
    m_transferred += written;
    return written;
}

} // namespace NetVfs::Bridge
