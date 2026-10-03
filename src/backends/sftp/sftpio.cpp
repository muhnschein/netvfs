// SPDX-License-Identifier: LGPL-2.1-or-later
// Transfers and handles (SPEC-sftp 7, S-21; SPEC-v2 XC-13, XC-14, XS-7).
#include "names.h"
#include "sftpinternal.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QIODevice>

#include <algorithm>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <memory>

namespace NetVfs::Sftp {

namespace {

constexpr qint64 MaxHandleRead = std::numeric_limits<int>::max();
// XS-7: read-ahead of a handle is capped at 4 MiB in flight.
constexpr quint64 MaxReadAheadBytes = 4 * 1024 * 1024;

// Reads up to `size` bytes; fewer only at the end of the source. -1 on error.
qint64 readFully(QIODevice *source, char *data, qint64 size)
{
    qint64 done = 0;
    while (done < size) {
        const qint64 n = source->read(data + done, size - done);
        if (n < 0)
            return -1;
        if (n == 0)
            break;
        done += n;
    }
    return done;
}

bool stopped(const std::atomic<bool> &canceled, const Progress *progress)
{
    return canceled || (progress && progress->canceled());
}

} // namespace

// Outstanding asynchronous requests, oldest first. Requests still queued when
// a transfer ends early are discarded: their answers are dropped on arrival
// (SPEC-sftp 7; vendor/patches/libssh/0002).
class SftpBackend::PendingQueue
{
public:
    PendingQueue() = default;
    PendingQueue(const PendingQueue &) = delete;
    PendingQueue &operator=(const PendingQueue &) = delete;
    ~PendingQueue() { discard(); }

    bool full(size_t limit = RequestWindow) const { return m_queue.size() >= limit; }
    bool empty() const { return m_queue.empty(); }
    size_t size() const { return m_queue.size(); }
    const Pending &front() const { return m_queue.front(); }
    void push(const Pending &pending) { m_queue.push_back(pending); }
    Pending take()
    {
        const Pending pending = m_queue.front();
        m_queue.pop_front();
        return pending;
    }
    void discard()
    {
        for (const Pending &pending : m_queue)
            sftp_aio_discard(pending.aio);
        m_queue.clear();
    }

private:
    std::deque<Pending> m_queue;
};

// Pipelined transfers over one open file (S-21, C-9, C-14).
class SftpBackend::Io
{
public:
    explicit Io(const SftpBackend &backend) : m_b(backend), m_q(backend) {}

    Result openForUpload(const QByteArray &remote, const WriteOptions &options, sftp_file *file) const;
    Result openForDownload(const QByteArray &remote, const DownloadOptions &options, sftp_file *file,
                           Sink *sink) const;

    Result timedOut() const;
    bool overdue(const QElapsedTimer &started) const;
    Result waitForData(const QElapsedTimer &started) const;
    Result waitWrite(Pending *pending, const QByteArray &remote) const;
    Result waitRead(Pending *pending, char *buffer, qint64 *received) const;
    Result beginRead(sftp_file file, size_t wanted, quint64 offset, Pending *pending) const;
    Result fillWriteWindow(sftp_file file, QIODevice *source, QByteArray *buffer, PendingQueue *queue, bool *eof,
                           const QByteArray &remote) const;
    Result writeChunks(sftp_file file, QIODevice *source, const QByteArray &remote, Progress *progress,
                       qint64 base) const;
    Result refillReadWindow(sftp_file file, PendingQueue *queue, quint64 *offset, quint64 end) const;
    Result readStep(sftp_file file, PendingQueue *queue, QByteArray *buffer, Sink *sink, quint64 *offset,
                    bool *finished) const;
    Result readChunks(sftp_file file, Sink *sink, quint64 start) const;

private:
    const SftpBackend &m_b;
    const Requests m_q;
};

// XC-13, XS-7: one open file. Reads are served from requests that are
// already on their way when the access is sequential or readAhead() asked
// for them, at most MaxReadAheadBytes (RequestWindow chunks) in flight.
// What a request brought beyond the bytes asked for is kept for the next
// read: never more than one chunk besides the answer of read() itself.
class SftpBackend::Reader : public ReadHandle
{
public:
    Reader(SftpBackend *backend, sftp_file file, qint64 size, const QByteArray &remote)
        : m_b(backend), m_file(file), m_size(size), m_remote(remote),
          m_window(std::max<size_t>(1, std::min<size_t>(RequestWindow, MaxReadAheadBytes / backend->m_readChunk)))
    {
    }
    Reader(const Reader &) = delete;
    Reader &operator=(const Reader &) = delete;
    ~Reader() override { release(); }

    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64 offset, qint64 bytes) override;
    Result close() override;

    // The backend closes the file because its connection ends.
    void invalidate();

private:
    int release();
    Result usable() const;
    void restartAt(quint64 offset);
    Result issue(quint64 until);
    bool takeBuffered(quint64 *position, quint64 end, QByteArray *out);
    Result receive(quint64 *position, quint64 end, QByteArray *out, bool *eof);
    void plan(quint64 offset, quint64 end);

    SftpBackend *m_b;
    sftp_file m_file;
    const qint64 m_size;
    const QByteArray m_remote;
    const size_t m_window;          // requests in flight at most
    bool m_lost = false;
    PendingQueue m_pending;         // contiguous, oldest first, ending at m_next
    quint64 m_next = 0;             // offset of the next request (the file's offset)
    QByteArray m_buffer;            // received, not handed out yet: [m_bufferOffset, +size)
    quint64 m_bufferOffset = 0;
    quint64 m_lastEnd = 0;          // end of the previous read(), for sequential access
    quint64 m_aheadBytes = 0;       // automatic read-ahead beyond a sequential read
    quint64 m_hintStart = 0;        // readAhead(): requests wanted for [start, end)
    quint64 m_hintEnd = 0;
};

// XC-13, XS-7: sequential, pipelined writes; errors of a request show at a
// later write() or at commit().
class SftpBackend::Writer : public WriteHandle
{
public:
    Writer(SftpBackend *backend, sftp_file file, const QByteArray &remote, qint64 position, const QDateTime &modified)
        : m_b(backend), m_file(file), m_remote(remote), m_position(position), m_modified(modified)
    {
    }
    Writer(const Writer &) = delete;
    Writer &operator=(const Writer &) = delete;
    ~Writer() override { release(); }

    Result write(const char *data, qint64 length) override;
    qint64 position() const override { return m_position; }
    Result commit() override;
    void abort() override;

    void invalidate();

private:
    void release();
    Result usable() const;
    Result finish();

    SftpBackend *m_b;
    sftp_file m_file;
    const QByteArray m_remote;
    qint64 m_position;
    const QDateTime m_modified;
    bool m_lost = false;
    Result m_failure;
    PendingQueue m_pending;
};

// --- Io -----------------------------------------------------------------------

Result SftpBackend::Io::timedOut() const
{
    return Result(Error::Timeout,
                  QStringLiteral("The server did not answer within %1 s").arg(m_b.m_params.requestTimeoutMs / 1000));
}

// A blocking read inside libssh that runs into the session timeout (the
// request timeout) fails without an error message. By then the request is
// overdue, and that is what the caller needs to know (C-14).
bool SftpBackend::Io::overdue(const QElapsedTimer &started) const
{
    return started.elapsed() >= m_b.m_params.requestTimeoutMs;
}

Result SftpBackend::Io::waitForData(const QElapsedTimer &started) const
{
    if (m_b.m_canceled)
        return canceled();   // C-9
    if (overdue(started))
        return timedOut();
    if (ssh_channel_poll_timeout(m_b.m_sftp->channel, PollIntervalMs, 0) == SSH_ERROR)
        return m_q.established(m_q.sessionFailure());
    return Result::success();
}

Result SftpBackend::Io::waitWrite(Pending *pending, const QByteArray &remote) const
{
    QElapsedTimer started;
    started.start();
    for (;;) {
        const ssize_t rc = sftp_aio_wait_write(&pending->aio);
        if (rc == SSH_AGAIN) {
            const Result r = waitForData(started);
            if (r.ok())
                continue;
            sftp_aio_discard(pending->aio);
            pending->aio = nullptr;
            return r;
        }
        if (rc < 0)
            return overdue(started) ? timedOut() : m_q.writeFailure(remote, static_cast<qint64>(pending->length));
        if (static_cast<size_t>(rc) != pending->length)
            return Result(Error::ProtocolError, QStringLiteral("The server stored only part of a block"));
        return Result::success();
    }
}

Result SftpBackend::Io::waitRead(Pending *pending, char *buffer, qint64 *received) const
{
    QElapsedTimer started;
    started.start();
    for (;;) {
        const ssize_t rc = sftp_aio_wait_read(&pending->aio, buffer, pending->length);
        if (rc == SSH_AGAIN) {
            const Result r = waitForData(started);
            if (r.ok())
                continue;
            sftp_aio_discard(pending->aio);
            pending->aio = nullptr;
            return r;
        }
        if (rc < 0)
            return overdue(started) ? timedOut() : m_q.sftpFailure(QStringLiteral("read"));
        *received = static_cast<qint64>(rc);
        return Result::success();
    }
}

Result SftpBackend::Io::beginRead(sftp_file file, size_t wanted, quint64 offset, Pending *pending) const
{
    const ssize_t rc = sftp_aio_begin_read(file, wanted, &pending->aio);
    if (rc <= 0)
        return m_q.sftpFailure(QStringLiteral("read"));
    pending->length = static_cast<size_t>(rc);
    pending->offset = offset;
    return Result::success();
}

Result SftpBackend::Io::fillWriteWindow(sftp_file file, QIODevice *source, QByteArray *buffer, PendingQueue *queue,
                                        bool *eof, const QByteArray &remote) const
{
    while (!*eof && !queue->full()) {
        const qint64 n = readFully(source, buffer->data(), buffer->size());
        if (n < 0)
            return Result(Error::Internal, QStringLiteral("Cannot read the local file"));
        *eof = n < buffer->size();
        for (qint64 sent = 0; sent < n;) {
            Pending pending;
            const ssize_t rc = sftp_aio_begin_write(file, buffer->constData() + sent,
                                                    static_cast<size_t>(n - sent), &pending.aio);
            if (rc <= 0)
                return m_q.writeFailure(remote, n - sent);
            pending.length = static_cast<size_t>(rc);
            queue->push(pending);
            sent += rc;
        }
    }
    return Result::success();
}

Result SftpBackend::Io::writeChunks(sftp_file file, QIODevice *source, const QByteArray &remote,
                                    Progress *progress, qint64 base) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_b.m_writeChunk), Qt::Uninitialized);
    const qint64 total = base + source->size();
    qint64 done = base;
    bool eof = false;
    for (;;) {
        if (stopped(m_b.m_canceled, progress))
            return canceled();
        Result r = fillWriteWindow(file, source, &buffer, &queue, &eof, remote);
        if (!r.ok() || queue.empty())
            return r;
        Pending pending = queue.take();
        r = waitWrite(&pending, remote);
        if (!r.ok())
            return r;
        done += static_cast<qint64>(pending.length);
        if (progress)
            progress->update(done, total);
    }
}

Result SftpBackend::Io::refillReadWindow(sftp_file file, PendingQueue *queue, quint64 *offset, quint64 end) const
{
    while (!queue->full() && *offset < end) {
        Pending pending;
        const auto wanted = static_cast<size_t>(std::min<quint64>(m_b.m_readChunk, end - *offset));
        if (const Result r = beginRead(file, wanted, *offset, &pending); !r.ok())
            return r;
        queue->push(pending);
        *offset += static_cast<quint64>(pending.length);
    }
    return Result::success();
}

Result SftpBackend::Io::readStep(sftp_file file, PendingQueue *queue, QByteArray *buffer, Sink *sink,
                                 quint64 *offset, bool *finished) const
{
    Pending pending = queue->take();
    qint64 n = 0;
    if (const Result r = waitRead(&pending, buffer->data(), &n); !r.ok())
        return r;
    if (n == 0) {
        *finished = true;   // end of file; the answers still due are dropped
        return Result::success();
    }
    if (sink->device->write(buffer->constData(), n) != n) {
        return Result(Error::NoSpace,
                      QStringLiteral("Cannot write the local file: %1").arg(sink->device->errorString()));
    }
    sink->done += n;
    if (sink->progress)
        sink->progress->update(sink->done, sink->total);
    if (static_cast<size_t>(n) == pending.length)
        return Result::success();
    // A short read: the requests already sent ask for the wrong offsets.
    // Drop their answers and continue after the data.
    *offset = pending.offset + static_cast<quint64>(n);
    queue->discard();
    if (sftp_seek64(file, *offset) < 0)
        return m_q.sftpFailure(QStringLiteral("seek"));
    return Result::success();
}

// Reads from `start` to the end of the file, or sink->limit bytes.
Result SftpBackend::Io::readChunks(sftp_file file, Sink *sink, quint64 start) const
{
    PendingQueue queue;
    QByteArray buffer(static_cast<int>(m_b.m_readChunk), Qt::Uninitialized);
    quint64 offset = start;
    const quint64 end = sink->limit < 0 ? std::numeric_limits<quint64>::max()
                                        : start + static_cast<quint64>(sink->limit);
    bool finished = false;
    while (!finished) {
        if (stopped(m_b.m_canceled, sink->progress))
            return canceled();   // C-9, between requests
        Result r = refillReadWindow(file, &queue, &offset, end);
        if (r.ok() && queue.empty())
            break;                            // everything wanted has arrived
        if (r.ok())
            r = readStep(file, &queue, &buffer, sink, &offset, &finished);
        if (!r.ok())
            return r;
    }
    return Result::success();
}

// --- upload, download -----------------------------------------------------------

Result SftpBackend::Io::openForUpload(const QByteArray &remote, const WriteOptions &options, sftp_file *file) const
{
    if (options.disposition == WriteOptions::Disposition::Resume && options.resumeOffset < 0)
        return invalidRange();
    int flags = O_WRONLY;
    if (options.disposition == WriteOptions::Disposition::CreateNew)
        flags |= O_CREAT | O_EXCL;
    else if (options.disposition == WriteOptions::Disposition::Truncate)
        flags |= O_CREAT | O_TRUNC;
    // XC-23: the requested mode, else the server's default (S-20 for backups
    // comes through TransferPolicy::createMode). Resume: no O_TRUNC, no O_CREAT.
    const mode_t mode = options.createMode >= 0 ? (static_cast<mode_t>(options.createMode) & PermissionBits)
                                                : DefaultFileMode;
    *file = sftp_open(m_b.m_sftp, remote.constData(), flags, mode);
    if (!*file) {
        const Result failure = m_q.sftpFailure(display(remote));
        Entry existing;
        if (failure.error() == Error::ConnectionLost || failure.error() == Error::Canceled
                || !m_q.statRemote(remote, &existing).ok())
            return failure;
        if (existing.isDir())
            return Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
        if (options.disposition == WriteOptions::Disposition::CreateNew)
            return Result(Error::AlreadyExists, QStringLiteral("%1 exists").arg(display(remote)));
        return failure;
    }
    if (options.disposition != WriteOptions::Disposition::Resume)
        return Result::success();
    // XC-13: the remote size must be the offset the caller continues at.
    Result r;
    if (sftp_attributes attributes = sftp_fstat(*file)) {
        const qint64 size = static_cast<qint64>(std::min<uint64_t>(attributes->size, std::numeric_limits<qint64>::max()));
        sftp_attributes_free(attributes);
        r = checkResumeOffset(size, options.resumeOffset);
    } else {
        r = m_q.sftpFailure(display(remote));
    }
    if (r.ok() && sftp_seek64(*file, static_cast<quint64>(options.resumeOffset)) < 0)
        r = m_q.sftpFailure(display(remote));
    if (!r.ok()) {
        m_q.closeFile(*file, !m_b.m_canceled);
        *file = nullptr;
    }
    return r;
}

Result SftpBackend::upload(QIODevice *source, const QString &path, const UploadOptions &options, Progress *progress)
{
    const Requests q(*this);
    const Io io(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    sftp_file file = nullptr;
    if (r.ok())
        r = io.openForUpload(remote, options.write, &file);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    const qint64 base = options.write.disposition == WriteOptions::Disposition::Resume ? options.write.resumeOffset : 0;
    r = io.writeChunks(file, source, remote, progress, base);
    if (r.ok() && m_hasFsync && sftp_fsync(file) != 0)   // C-12: flush to stable storage
        r = q.writeFailure(remote, 1);
    const int closed = q.closeFile(file, r.ok());
    if (r.ok() && closed != 0)
        r = q.writeFailure(remote, 1);
    // XC-14: SetModifiedOnUpload.
    if (r.ok() && options.write.modified.isValid())
        r = q.setTimes(remote, options.write.modified, QDateTime(), -1);
    return r;
}

Result SftpBackend::Io::openForDownload(const QByteArray &remote, const DownloadOptions &options, sftp_file *file,
                                       Sink *sink) const
{
    if (options.offset < 0 || options.length < -1)
        return invalidRange();
    *file = sftp_open(m_b.m_sftp, remote.constData(), O_RDONLY, 0);
    if (!*file)
        return m_q.sftpFailure(display(remote));
    Result r;
    if (sftp_attributes attributes = sftp_fstat(*file)) {
        const Entry entry = entryFrom(*attributes, QString());
        sftp_attributes_free(attributes);
        if (entry.type == EntryType::Directory)
            r = Result(Error::IsADirectory, QStringLiteral("%1 is a folder").arg(display(remote)));
        sink->total = entry.size < 0 ? -1 : qMax<qint64>(0, entry.size - options.offset);
    }
    if (options.length >= 0)
        sink->total = sink->total < 0 ? options.length : qMin(sink->total, options.length);
    sink->limit = options.length;
    if (r.ok() && options.offset > 0 && sftp_seek64(*file, static_cast<quint64>(options.offset)) < 0)
        r = m_q.sftpFailure(display(remote));
    if (!r.ok()) {
        m_q.closeFile(*file, !m_b.m_canceled);
        *file = nullptr;
    }
    return r;
}

Result SftpBackend::download(const QString &path, QIODevice *sink, const DownloadOptions &options, Progress *progress)
{
    const Requests q(*this);
    const Io io(*this);
    QByteArray remote;
    Result r = q.ready(path, &remote);
    sftp_file file = nullptr;
    Sink target { sink, progress, -1, 0, -1 };
    if (r.ok())
        r = io.openForDownload(remote, options, &file, &target);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    r = io.readChunks(file, &target, static_cast<quint64>(options.offset));
    q.closeFile(file, r.ok());
    return r;
}

// --- handles ------------------------------------------------------------------

void SftpBackend::Connection::invalidateHandles()
{
    for (Reader *reader : m_b.m_readers)
        reader->invalidate();
    m_b.m_readers.clear();
    for (Writer *writer : m_b.m_writers)
        writer->invalidate();
    m_b.m_writers.clear();
}

Result SftpBackend::openRead(const QString &path, ReadHandle **out)
{
    *out = nullptr;
    QByteArray remote;
    Result r = Requests(*this).ready(path, &remote);
    sftp_file file = nullptr;
    Sink probe;
    if (r.ok())
        r = Io(*this).openForDownload(remote, DownloadOptions(), &file, &probe);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    auto reader = std::make_unique<Reader>(this, file, probe.total, remote);
    m_readers.insert(reader.get());
    *out = reader.release();   // XC-13: the caller owns the handle
    return r;
}

Result SftpBackend::openWrite(const QString &path, const WriteOptions &options, WriteHandle **out)
{
    *out = nullptr;
    QByteArray remote;
    Result r = Requests(*this).ready(path, &remote);
    sftp_file file = nullptr;
    if (r.ok())
        r = Io(*this).openForUpload(remote, options, &file);
    if (!r.ok())
        return r;
    sftp_file_set_nonblocking(file);
    const qint64 position = options.disposition == WriteOptions::Disposition::Resume ? options.resumeOffset : 0;
    auto writer = std::make_unique<Writer>(this, file, remote, position, options.modified);
    m_writers.insert(writer.get());
    *out = writer.release();   // XC-13: the caller owns the handle
    return r;
}

// --- Reader -------------------------------------------------------------------

void SftpBackend::Reader::invalidate()
{
    if (m_file && m_b->m_sftp) {
        m_pending.discard();
        Requests(*m_b).closeFile(m_file, false);
    }
    m_file = nullptr;
    m_lost = true;
}

Result SftpBackend::Reader::usable() const
{
    if (m_lost)
        return handleLost();
    if (!m_file)
        return Result(Error::Internal, QStringLiteral("The file is closed"));
    return Result::success();
}

void SftpBackend::Reader::restartAt(quint64 offset)
{
    // Answers to requests for other offsets are dropped when they arrive.
    m_pending.discard();
    m_next = offset;
}

Result SftpBackend::Reader::issue(quint64 until)
{
    if (m_pending.empty() && sftp_seek64(m_file, m_next) < 0)
        return Requests(*m_b).sftpFailure(display(m_remote));
    while (!m_pending.full(m_window) && m_next < until) {
        Pending pending;
        const auto wanted = static_cast<size_t>(std::min<quint64>(m_b->m_readChunk, until - m_next));
        if (const Result r = Io(*m_b).beginRead(m_file, wanted, m_next, &pending); !r.ok())
            return r;
        m_pending.push(pending);
        m_next += static_cast<quint64>(pending.length);
    }
    return Result::success();
}

bool SftpBackend::Reader::takeBuffered(quint64 *position, quint64 end, QByteArray *out)
{
    const quint64 bufferEnd = m_bufferOffset + static_cast<quint64>(m_buffer.size());
    if (m_buffer.isEmpty() || *position < m_bufferOffset || *position >= bufferEnd) {
        m_buffer.clear();
        return false;
    }
    const auto skip = static_cast<int>(*position - m_bufferOffset);
    const auto n = static_cast<int>(std::min<quint64>(bufferEnd - *position, end - *position));
    out->append(m_buffer.constData() + skip, n);
    *position += static_cast<quint64>(n);
    if (*position >= bufferEnd)
        m_buffer.clear();
    return true;
}

// Waits for the oldest request and hands out what is wanted of its answer;
// the rest of it stays in m_buffer.
Result SftpBackend::Reader::receive(quint64 *position, quint64 end, QByteArray *out, bool *eof)
{
    Pending pending = m_pending.take();
    QByteArray data(static_cast<int>(pending.length), Qt::Uninitialized);
    qint64 n = 0;
    if (const Result r = Io(*m_b).waitRead(&pending, data.data(), &n); !r.ok()) {
        restartAt(*position);
        return r;
    }
    if (n == 0) {
        *eof = true;
        restartAt(*position);
        return Result::success();
    }
    data.truncate(static_cast<int>(n));
    const auto used = static_cast<int>(std::min<quint64>(static_cast<quint64>(n), end - *position));
    out->append(data.constData(), used);
    *position += static_cast<quint64>(used);
    if (used < n) {
        m_buffer = data.mid(used);
        m_bufferOffset = *position;
    }
    // A short answer leaves a hole before the next request's data.
    if (static_cast<size_t>(n) < pending.length)
        restartAt(pending.offset + static_cast<quint64>(n));
    return Result::success();
}

void SftpBackend::Reader::plan(quint64 offset, quint64 end)
{
    // Sequential reads grow the automatic read-ahead up to the cap; a jump
    // ends it (archives and previews read here and there).
    const quint64 cap = m_window * m_b->m_readChunk;
    if (offset == m_lastEnd && offset > 0)
        m_aheadBytes = std::min(cap, std::max<quint64>(m_aheadBytes * 2, m_b->m_readChunk));
    else
        m_aheadBytes = 0;
    m_lastEnd = end;
}

Result SftpBackend::Reader::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (out)
        out->clear();
    if (Result r = usable(); !r.ok())
        return r;
    if (offset < 0 || maxBytes < 0 || maxBytes > MaxHandleRead)
        return invalidRange();
    if (Result r = Requests(*m_b).checkReady(); !r.ok() || maxBytes == 0)
        return r;
    QByteArray data;
    auto position = static_cast<quint64>(offset);
    const quint64 end = position + static_cast<quint64>(maxBytes);
    plan(position, end);
    takeBuffered(&position, end, &data);
    // Requests already on their way for other offsets are dropped (a read
    // the kept chunk answered completely leaves them alone).
    if (position < end && !m_pending.empty() && m_pending.front().offset != position)
        restartAt(position);
    if (m_pending.empty())
        m_next = position;
    bool eof = false;
    while (position < end && !eof) {
        if (m_b->m_canceled)
            return canceled();   // C-9
        const bool hinted = m_hintStart <= end && m_hintEnd > position;
        const quint64 wanted = std::max(end + m_aheadBytes, hinted ? m_hintEnd : end);
        Result r = issue(std::min(wanted, end + m_window * m_b->m_readChunk));
        if (r.ok())
            r = receive(&position, end, &data, &eof);
        if (!r.ok())
            return r;
    }
    if (out)
        *out = data;
    return Result::success();
}

void SftpBackend::Reader::readAhead(qint64 offset, qint64 bytes)
{
    // A hint: requests go out now when they continue what is already
    // asked for (or nothing is); otherwise it is ignored. Errors show at
    // the next read().
    if (!usable().ok() || !Requests(*m_b).checkReady().ok() || offset < 0 || bytes <= 0)
        return;
    const auto start = static_cast<quint64>(offset);
    if (m_pending.empty()) {
        const quint64 bufferEnd = m_bufferOffset + static_cast<quint64>(m_buffer.size());
        if (m_buffer.isEmpty() || start < m_bufferOffset || start > bufferEnd) {
            m_buffer.clear();
            m_next = start;
        } else {
            m_next = bufferEnd;
        }
    } else if (start < m_pending.front().offset || start > m_next) {
        return;
    }
    m_hintStart = start;
    m_hintEnd = std::min(start + static_cast<quint64>(bytes), start + MaxReadAheadBytes);
    issue(m_hintEnd);
}

int SftpBackend::Reader::release()
{
    if (!m_file)
        return 0;
    m_pending.discard();
    m_buffer.clear();
    const int rc = Requests(*m_b).closeFile(m_file, !m_b->m_canceled);
    m_file = nullptr;
    m_b->m_readers.remove(this);
    return rc;
}

Result SftpBackend::Reader::close()
{
    if (!m_file)
        return m_lost ? handleLost() : Result();
    const int rc = release();
    if (m_b->m_canceled)
        return canceled();
    return rc == 0 ? Result::success() : Requests(*m_b).sftpFailure(display(m_remote));
}

// --- Writer -------------------------------------------------------------------

void SftpBackend::Writer::invalidate()
{
    if (m_file && m_b->m_sftp) {
        m_pending.discard();
        Requests(*m_b).closeFile(m_file, false);
    }
    m_file = nullptr;
    m_lost = true;
}

Result SftpBackend::Writer::usable() const
{
    if (m_lost)
        return handleLost();
    if (!m_file)
        return Result(Error::Internal, QStringLiteral("The file is closed"));
    if (!m_failure.ok())
        return m_failure;
    return Requests(*m_b).checkReady();
}

Result SftpBackend::Writer::write(const char *data, qint64 length)
{
    if (Result r = usable(); !r.ok())
        return r;
    if (length < 0 || (length > 0 && !data))
        return invalidRange();
    const Io io(*m_b);
    while (length > 0 && m_failure.ok()) {
        if (m_b->m_canceled)
            return canceled();   // C-9, nothing in doubt yet
        if (m_pending.full()) {
            // A canceled wait leaves the fate of that block unknown: the
            // handle stays failed (resume from the remote size instead).
            Pending oldest = m_pending.take();
            m_failure = io.waitWrite(&oldest, m_remote);
            continue;
        }
        Pending pending;
        const auto chunk = static_cast<size_t>(std::min<qint64>(length, static_cast<qint64>(m_b->m_writeChunk)));
        const ssize_t rc = sftp_aio_begin_write(m_file, data, chunk, &pending.aio);
        if (rc <= 0) {
            m_failure = Requests(*m_b).writeFailure(m_remote, static_cast<qint64>(chunk));
            break;
        }
        pending.length = static_cast<size_t>(rc);
        m_pending.push(pending);
        data += rc;
        length -= rc;
        m_position += rc;
    }
    return m_failure;
}

Result SftpBackend::Writer::finish()
{
    // Every block acknowledged, then fsync@openssh.com when offered (C-12).
    const Io io(*m_b);
    Result r = m_failure;
    while (r.ok() && !m_pending.empty()) {
        Pending oldest = m_pending.take();
        r = io.waitWrite(&oldest, m_remote);
    }
    if (r.ok() && m_b->m_hasFsync && sftp_fsync(m_file) != 0)
        r = Requests(*m_b).writeFailure(m_remote, 1);
    return r;
}

Result SftpBackend::Writer::commit()
{
    if (Result r = usable(); !r.ok()) {
        release();
        return r;
    }
    Result r = finish();
    m_pending.discard();
    const int closed = Requests(*m_b).closeFile(m_file, r.ok());
    m_file = nullptr;
    m_b->m_writers.remove(this);
    if (r.ok() && closed != 0)
        r = Requests(*m_b).writeFailure(m_remote, 1);
    // XC-13: the modification time is applied on commit (SetModified).
    if (r.ok() && m_modified.isValid())
        r = Requests(*m_b).setTimes(m_remote, m_modified, QDateTime(), -1);
    return r;
}

void SftpBackend::Writer::abort()
{
    release();
}

void SftpBackend::Writer::release()
{
    if (!m_file)
        return;
    m_pending.discard();
    Requests(*m_b).closeFile(m_file, false);
    m_file = nullptr;
    m_b->m_writers.remove(this);
}

} // namespace NetVfs::Sftp
