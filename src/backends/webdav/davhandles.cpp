// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davhandles.h"
#include "webdavbackend.h"

namespace NetVfs::WebDav {

namespace {

// One read() holds at most this much (C-10); larger requests return less,
// which callers handle like any short read before EOF would be.
constexpr qint64 MaxReadBytes = qint64(1) << 30;

Result disconnected()
{
    return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
}

qint64 announcedLength(const WriteOptions &options)
{
    if (options.expectedSize < 0)
        return -1;
    if (options.disposition == WriteOptions::Resume)
        return options.expectedSize - options.resumeOffset;
    return options.expectedSize;
}

} // namespace

DavReadHandle::DavReadHandle(std::shared_ptr<HandleLink> link, const QByteArray &url, qint64 size)
    : m_link(std::move(link))
    , m_url(url)
    , m_size(size)
{
}

Result DavReadHandle::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    out->clear();
    if (m_closed)
        return Result(Error::Internal, QStringLiteral("The file is closed"));
    if (!m_link->backend)
        return disconnected();
    if (offset < 0 || maxBytes < 0)
        return Result(Error::Internal, QStringLiteral("Invalid range"));
    qint64 want = qMin(maxBytes, MaxReadBytes);
    if (m_size >= 0)
        want = qMin(want, m_size - offset);
    // XC-13: short reads only at EOF, so a server that sends fewer bytes
    // than asked for is asked again.
    while (want > out->size()) {
        QByteArray chunk;
        const Result r = m_link->backend->readRange(m_url, offset + out->size(), want - out->size(), &chunk);
        if (!r.ok()) {
            out->clear();
            return r;
        }
        if (chunk.isEmpty())
            break;
        out->append(chunk);
    }
    return Result::success();
}

Result DavReadHandle::close()
{
    m_closed = true;
    return m_link->backend ? Result::success() : disconnected();
}

DavWriteHandle::DavWriteHandle(std::shared_ptr<HandleLink> link, std::unique_ptr<Client::Stream> stream,
                               const QString &path, const WriteOptions &options)
    : m_link(std::move(link))
    , m_stream(std::move(stream))
    , m_path(path)
    , m_options(options)
    , m_announced(announcedLength(options))
    , m_complete(!m_stream)
{
}

DavWriteHandle::~DavWriteHandle()
{
    abort();
}

void DavWriteHandle::release()
{
    if (m_released)
        return;
    m_released = true;
    if (m_stream)
        m_stream->abort();
    m_stream.reset();
    if (m_link->backend)
        m_link->backend->writeHandleClosed();
}

Result DavWriteHandle::write(const char *data, qint64 length)
{
    if (!m_failure.ok())
        return m_failure;
    if (m_complete)
        return Result(Error::Internal, QStringLiteral("The file is already complete"));
    if (!m_link->backend || !m_stream)
        return disconnected();
    if (length < 0 || (m_announced >= 0 && m_position + length > m_announced)) {
        m_failure = Result(Error::Internal, QStringLiteral("More data than the announced %1 bytes").arg(m_announced));
        release();
        return m_failure;
    }
    Result r = m_stream->write(data, length);
    if (!r.ok() && m_stream->answered()) {
        // The server ended the request early (413, 507, ...): its status says why.
        const Result answer = m_link->backend->finishWrite(m_stream.get(), m_path, m_options);
        if (!answer.ok())
            r = answer;
    }
    if (!r.ok()) {
        m_failure = r;
        release();
        return r;
    }
    m_position += length;
    return r;
}

Result DavWriteHandle::commit()
{
    if (!m_failure.ok() || m_complete)
        return m_failure;
    if (!m_link->backend || !m_stream)
        return disconnected();
    if (m_announced >= 0 && m_position != m_announced) {
        m_failure = Result(Error::Internal, QStringLiteral("Wrote %1 of the announced %2 bytes").arg(m_position).arg(m_announced));
        release();
        return m_failure;
    }
    const Result r = m_link->backend->finishWrite(m_stream.get(), m_path, m_options);
    release();
    m_complete = r.ok();
    if (!r.ok())
        m_failure = r;
    return r;
}

void DavWriteHandle::abort()
{
    release();
}

} // namespace NetVfs::WebDav
