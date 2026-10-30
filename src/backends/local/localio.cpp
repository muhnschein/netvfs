// SPDX-License-Identifier: LGPL-2.1-or-later
#include "localhandles.h"
#include "names.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QIODevice>

#include <array>
#include <cerrno>
#include <limits>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace NetVfs::Local {

namespace {

constexpr mode_t DefaultFileMode = 0666;
constexpr int MaxTemporaryAttempts = 16;
constexpr qint64 MaxReadBytes = std::numeric_limits<int>::max() / 2;

Result handleLost()
{
    return Result(Error::ConnectionLost, QStringLiteral("The connection of this handle was closed"));
}

Result handleClosed()
{
    return Result(Error::Internal, QStringLiteral("The handle is closed"));
}

Result canceled()
{
    return Result(Error::Canceled);
}

bool isStream(const NativeStat &st)
{
    return st.type != EntryType::File;
}

// copy_file_range(2) through syscall(): glibc 2.27..2.29 emulated it in user space without cancel
// checks.
long copyRange(int source, int target, qint64 length)
{
#ifdef SYS_copy_file_range
    return ::syscall(SYS_copy_file_range, source, nullptr, target, nullptr, static_cast<size_t>(length), 0U);
#else
    Q_UNUSED(source)
    Q_UNUSED(target)
    Q_UNUSED(length)
    errno = ENOSYS;
    return -1;
#endif
}

bool cloned(int source, int target)
{
#ifdef FICLONE
    return ::ioctl(target, FICLONE, source) == 0;
#else
    Q_UNUSED(source)
    Q_UNUSED(target)
    return false;
#endif
}

Result copyByReading(int source, int target, const Waiter &waiter)
{
    QByteArray buffer(static_cast<int>(ChunkSize), Qt::Uninitialized);
    for (;;) {
        if (const Result r = waiter.check(); !r.ok())
            return r;
        qint64 n = 0;
        if (const Result r = readOnce(source, -1, buffer.data(), ChunkSize, waiter, &n); !r.ok())
            return r;
        if (n == 0)
            return Result::success();
        if (const Result r = writeFully(target, buffer.constData(), n, waiter); !r.ok())
            return r;
    }
}

Result copyData(int source, int target, const Waiter &waiter)
{
    if (cloned(source, target))
        return Result::success();
    bool started = false;
    for (;;) {
        if (const Result r = waiter.check(); !r.ok())
            return r;
        const long n = copyRange(source, target, ChunkSize);
        if (n == 0)
            return Result::success();
        if (n > 0) {
            started = true;
            continue;
        }
        if (errno == EINTR)
            continue;
        if (started || (errno != EXDEV && errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP
                        && errno != EBADF))
            return errnoResult(errno, QStringLiteral("Cannot copy"));
        return copyByReading(source, target, waiter);
    }
}

bool algorithmFor(const QString &name, QCryptographicHash::Algorithm *out)
{
    if (name == QLatin1String("sha256"))
        *out = QCryptographicHash::Sha256;
    else if (name == QLatin1String("sha1"))
        *out = QCryptographicHash::Sha1;
    else if (name == QLatin1String("md5"))
        *out = QCryptographicHash::Md5;
    else
        return false;
    return true;
}

QByteArray temporaryName(const QByteArray &target, int attempt)
{
    static std::atomic<quint32> counter { 0 };
    return parentOf(target) + "/.netvfs-copy-" + QByteArray::number(::getpid()) + '-'
        + QByteArray::number(++counter) + '-' + QByteArray::number(attempt);
}

Result openForRead(const QByteArray &native, Fd *fd, NativeStat *st)
{
    // O_NONBLOCK: opening a FIFO without a writer must not block; reads wait in Waiter. No effect
    // on regular files.
    Fd file(::open(native.constData(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!file.valid())
        return errnoResult(errno, display(native));
    if (const int e = statFd(file.get(), st); e != 0)
        return errnoResult(e, display(native));
    if (st->isDir())
        return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(native)));
    *fd = std::move(file);
    return Result::success();
}

Result openForWrite(const QByteArray &native, const WriteOptions &options, Fd *fd)
{
    if (options.createMode < -1 || options.createMode > 07777)
        return Result(Error::Internal, QStringLiteral("Invalid mode %1").arg(options.createMode, 0, 8));
    if (options.disposition == WriteOptions::Disposition::Resume && options.resumeOffset < 0)
        return Result(Error::Internal, QStringLiteral("Invalid resume offset"));
    int flags = O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
    if (options.disposition == WriteOptions::Disposition::CreateNew)
        flags |= O_CREAT | O_EXCL;
    else if (options.disposition == WriteOptions::Disposition::Truncate)
        flags |= O_CREAT | O_TRUNC;
    const mode_t mode = options.createMode >= 0 ? static_cast<mode_t>(options.createMode) : DefaultFileMode;
    Fd file(::open(native.constData(), flags, mode));
    if (!file.valid())
        return errnoResult(errno, display(native));
    if (options.disposition == WriteOptions::Disposition::Resume) {
        NativeStat st;
        if (const int e = statFd(file.get(), &st); e != 0)
            return errnoResult(e, display(native));
        if (st.size != options.resumeOffset) {
            return Result(Error::ProtocolError, QStringLiteral("Cannot resume %1 at %2: the file has %3 bytes")
                                                    .arg(display(native)).arg(options.resumeOffset).arg(st.size));
        }
        if (::lseek(file.get(), options.resumeOffset, SEEK_SET) < 0 && errno != ESPIPE)
            return errnoResult(errno, display(native));
    }
    *fd = std::move(file);
    return Result::success();
}

Result copyInto(int source, const QByteArray &target, const NativeStat &st, int flags,
                const Waiter &waiter)
{
    Fd output(::open(target.constData(), O_WRONLY | O_CLOEXEC | O_NOCTTY | flags,
                     static_cast<mode_t>(st.mode & 0777)));
    if (!output.valid())
        return errnoResult(errno, display(target));
    Result r = copyData(source, output.get(), waiter);
    if (r.ok()) {
        if (const std::array<struct timespec, 2> times = { toTimespec(fromMsecs(st.accessedMs)),
                                                           toTimespec(fromMsecs(st.modifiedMs)) };
                ::futimens(output.get(), times.data()) != 0)
            qCDebug(lcNetVfsLocal) << "Cannot keep the modification time of a copy";
        if (const int e = output.close(); e != 0)
            r = errnoResult(e, display(target));
    }
    if (!r.ok()) {
        output.reset();
        ::unlink(target.constData());
    }
    return r;
}

Result copyReplacing(int source, const QByteArray &target, const NativeStat &st, const Waiter &waiter)
{
    for (int attempt = 0; attempt < MaxTemporaryAttempts; ++attempt) {
        const QByteArray temporary = temporaryName(target, attempt);
        const Result r = copyInto(source, temporary, st, O_CREAT | O_EXCL, waiter);
        if (r.error() == Error::AlreadyExists)
            continue;
        if (!r.ok())
            return r;
        if (::rename(temporary.constData(), target.constData()) != 0) {
            const int error = errno;
            ::unlink(temporary.constData());
            return errnoResult(error, display(target));
        }
        syncFolder(parentOf(target));
        return Result::success();
    }
    return Result(Error::Internal, QStringLiteral("No free temporary name next to %1").arg(display(target)));
}

qint64 downloadTotal(const DownloadOptions &options, const NativeStat &st)
{
    if (isStream(st))
        return options.length;
    const qint64 available = qMax<qint64>(0, st.size - options.offset);
    return options.length < 0 ? available : qMin(options.length, available);
}

qint64 uploadTotal(const WriteOptions &write, const QIODevice *source)
{
    if (write.expectedSize >= 0)
        return write.expectedSize;
    return source->isSequential() ? -1 : source->size();
}

Result pumpDownload(int fd, const DownloadOptions &options, bool stream, QIODevice *sink, qint64 total,
                    Progress *progress, const Waiter &waiter)
{
    QByteArray buffer(static_cast<int>(ChunkSize), Qt::Uninitialized);
    qint64 done = 0;
    while (options.length < 0 || done < options.length) {
        if (waiter.canceled() || (progress && progress->canceled()))
            return canceled();
        const qint64 want = options.length < 0 ? ChunkSize : qMin(ChunkSize, options.length - done);
        qint64 n = 0;
        if (const Result r = readOnce(fd, stream ? -1 : options.offset + done, buffer.data(), want, waiter, &n);
                !r.ok())
            return r;
        if (n == 0)
            break;
        if (sink->write(buffer.constData(), n) != n)
            return Result(Error::NoSpace, QStringLiteral("Cannot write the local file: %1").arg(sink->errorString()));
        done += n;
        if (progress)
            progress->update(done, total);
    }
    return Result::success();
}

}
LocalReadHandle::LocalReadHandle(std::shared_ptr<Context> context, Fd fd, const NativeStat &st)
    : m_context(std::move(context))
    , m_generation(m_context->generation)
    , m_fd(std::move(fd))
    , m_size(isStream(st) ? -1 : st.size)
    , m_seekable(!isStream(st))
{
}

qint64 LocalReadHandle::size() const
{
    return m_size;
}

Result LocalReadHandle::check()
{
    if (m_context->generation != m_generation) {
        m_fd.reset();
        return handleLost();
    }
    if (!m_fd.valid())
        return handleClosed();
    if (m_context->canceled)
        return canceled();
    return Result::success();
}

Result LocalReadHandle::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (const Result r = check(); !r.ok())
        return r;
    if (offset < 0 || maxBytes < 0 || maxBytes > MaxReadBytes)
        return Result(Error::Internal, QStringLiteral("Invalid range"));
    if (!m_seekable && offset != m_streamPosition)
        return Result(Error::Unsupported, QStringLiteral("This file can only be read sequentially"));
    qint64 want = maxBytes;
    if (m_seekable) {
        NativeStat st;
        if (const int e = statFd(m_fd.get(), &st); e != 0)
            return errnoResult(e, QStringLiteral("Cannot read"));
        want = qBound<qint64>(0, st.size - offset, maxBytes);
    }
    QByteArray data(static_cast<int>(want), Qt::Uninitialized);
    qint64 got = 0;
    if (const Result r = readFully(m_fd.get(), m_seekable ? offset : -1, data.data(), want, m_context->waiter(), &got);
            !r.ok())
        return r;
    data.resize(static_cast<int>(got));
    m_streamPosition += m_seekable ? 0 : got;
    if (out)
        *out = data;
    return Result::success();
}

void LocalReadHandle::readAhead(qint64 offset, qint64 bytes)
{
    if (m_seekable && check().ok() && offset >= 0 && bytes > 0)
        ::posix_fadvise(m_fd.get(), offset, bytes, POSIX_FADV_WILLNEED);
}

Result LocalReadHandle::close()
{
    if (m_context->generation != m_generation) {
        m_fd.reset();
        return handleLost();
    }
    if (const int e = m_fd.close(); e != 0)
        return errnoResult(e, QStringLiteral("Cannot close"));
    return Result::success();
}

LocalWriteHandle::LocalWriteHandle(std::shared_ptr<Context> context, Fd fd, qint64 position,
                                   const QDateTime &modified)
    : m_context(std::move(context))
    , m_generation(m_context->generation)
    , m_fd(std::move(fd))
    , m_position(position)
    , m_modified(modified)
{
}

Result LocalWriteHandle::check()
{
    if (m_context->generation != m_generation) {
        m_fd.reset();
        return handleLost();
    }
    if (!m_fd.valid())
        return handleClosed();
    if (m_context->canceled)
        return canceled();
    return Result::success();
}

Result LocalWriteHandle::write(const char *data, qint64 length)
{
    if (const Result r = check(); !r.ok())
        return r;
    if (length < 0 || (length > 0 && !data))
        return Result(Error::Internal, QStringLiteral("Invalid buffer"));
    if (const Result r = writeFully(m_fd.get(), data, length, m_context->waiter()); !r.ok())
        return r;
    m_position += length;
    return Result::success();
}

qint64 LocalWriteHandle::position() const
{
    return m_position;
}

Result LocalWriteHandle::commit()
{
    if (const Result r = check(); !r.ok()) {
        m_fd.reset();
        return r;
    }
    const int fd = m_fd.get();
    if (fd < 0)
        return handleClosed();
    // Data on stable storage before the caller renames it into place. FIFOs and devices have
    // nothing to flush (EINVAL).
    if (::fsync(fd) != 0 && errno != EINVAL && errno != EROFS) {
        const int error = errno;
        m_fd.reset();
        return errnoResult(error, QStringLiteral("Cannot flush"));
    }
    if (m_modified.isValid()) {
        if (const std::array<struct timespec, 2> times = { toTimespec(QDateTime()), toTimespec(m_modified) };
                ::futimens(m_fd.get(), times.data()) != 0) {
            const int error = errno;
            m_fd.reset();
            return errnoResult(error, QStringLiteral("Cannot set the modification time"));
        }
    }
    if (const int e = m_fd.close(); e != 0)
        return errnoResult(e, QStringLiteral("Cannot close"));
    return Result::success();
}

void LocalWriteHandle::abort()
{
    m_fd.reset();
}

Result LocalBackend::openRead(const QString &path, ReadHandle **out)
{
    if (!out)
        return Result(Error::Internal, QStringLiteral("No handle pointer"));
    *out = nullptr;
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    Fd fd;
    NativeStat st;
    if (const Result r = openForRead(native, &fd, &st); !r.ok())
        return r;
    *out = std::make_unique<LocalReadHandle>(m_context, std::move(fd), st).release();
    return Result::success();
}

Result LocalBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    if (!out)
        return Result(Error::Internal, QStringLiteral("No handle pointer"));
    *out = nullptr;
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    Fd fd;
    if (const Result r = openForWrite(native, options, &fd); !r.ok())
        return r;
    const qint64 position = options.disposition == WriteOptions::Disposition::Resume ? options.resumeOffset : 0;
    *out = std::make_unique<LocalWriteHandle>(m_context, std::move(fd), position, options.modified).release();
    return Result::success();
}

Result LocalBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options,
                            Progress *progress)
{
    if (!source)
        return Result(Error::Internal, QStringLiteral("No source"));
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    Fd fd;
    if (const Result r = openForWrite(native, options.write, &fd); !r.ok())
        return r;
    const WriteOptions &write = options.write;
    LocalWriteHandle handle(m_context, std::move(fd),
                            write.disposition == WriteOptions::Disposition::Resume ? write.resumeOffset : 0, write.modified);
    const qint64 total = uploadTotal(write, source);
    QByteArray buffer(static_cast<int>(ChunkSize), Qt::Uninitialized);
    for (;;) {
        if (progress && progress->canceled()) {
            handle.abort();
            return canceled();
        }
        const qint64 n = source->read(buffer.data(), buffer.size());
        if (n < 0) {
            handle.abort();
            return Result(Error::Internal, QStringLiteral("Cannot read the source: %1").arg(source->errorString()));
        }
        if (n == 0)
            break;
        if (const Result r = handle.write(buffer.constData(), n); !r.ok()) {
            handle.abort();
            return r;
        }
        if (progress)
            progress->update(handle.position(), total);
    }
    return handle.commit();
}

Result LocalBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options,
                              Progress *progress)
{
    if (!sink)
        return Result(Error::Internal, QStringLiteral("No sink"));
    if (options.offset < 0 || options.length < -1)
        return Result(Error::Internal, QStringLiteral("Invalid range"));
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    Fd fd;
    NativeStat st;
    if (const Result r = openForRead(native, &fd, &st); !r.ok())
        return r;
    const bool stream = isStream(st);
    if (stream && options.offset > 0)
        return Result(Error::Unsupported, QStringLiteral("%1 can only be read sequentially").arg(display(native)));
    return pumpDownload(fd.get(), options, stream, sink, downloadTotal(options, st), progress, m_context->waiter());
}

Result LocalBackend::copy(const QString &from, const QString &to, const CopyOptions &options)
{
    QByteArray source;
    QByteArray target;
    Result r = prepare(from, &source);
    if (r.ok())
        r = resolve(to, &target);
    if (!r.ok())
        return r;
    Fd input;
    NativeStat st;
    r = openForRead(source, &input, &st);
    if (r.error() == Error::IsADirectory)
        return Result(Error::Unsupported, QStringLiteral("Copying folders is not supported by this backend"));
    if (!r.ok())
        return r;
    if (st.type != EntryType::File)
        return Result(Error::Unsupported, QStringLiteral("%1 is not a regular file").arg(display(source)));
    if (options.mode == RenameMode::NoReplace)
        return copyInto(input.get(), target, st, O_CREAT | O_EXCL, m_context->waiter());
    if (NativeStat existing; statAt(AT_FDCWD, target, false, &existing) == 0 && existing.isDir())
        return Result(Error::AlreadyExists, QStringLiteral("%1 is a folder and is not replaced").arg(display(target)));
    return copyReplacing(input.get(), target, st, m_context->waiter());
}

Result LocalBackend::checksum(const QString &path, const QString &algorithm, QByteArray *digest)
{
    QCryptographicHash::Algorithm kind {};
    if (!algorithmFor(algorithm, &kind))
        return Result(Error::Unsupported, QStringLiteral("Checksum algorithm \"%1\" is not supported").arg(algorithm));
    QByteArray native;
    if (const Result r = prepare(path, &native); !r.ok())
        return r;
    Fd fd;
    NativeStat st;
    if (const Result r = openForRead(native, &fd, &st); !r.ok())
        return r;
    const Waiter waiter = m_context->waiter();
    QCryptographicHash hash(kind);
    QByteArray buffer(static_cast<int>(ChunkSize), Qt::Uninitialized);
    for (qint64 position = 0;;) {
        if (const Result r = waiter.check(); !r.ok())
            return r;
        qint64 n = 0;
        if (const Result r = readOnce(fd.get(), isStream(st) ? -1 : position, buffer.data(), ChunkSize, waiter, &n);
                !r.ok())
            return r;
        if (n == 0)
            break;
        hash.addData(buffer.constData(), static_cast<int>(n));
        position += n;
    }
    if (digest)
        *digest = hash.result();
    return Result::success();
}

}