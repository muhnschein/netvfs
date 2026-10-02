// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftphandles.h"

#include <algorithm>

namespace NetVfs::Ftp {

namespace {

Result lost()
{
    return Result(Error::ConnectionLost, QStringLiteral("The connection was closed"));
}

} // namespace

// ---------------------------------------------------------------- read handle

FtpReadHandle::FtpReadHandle(FtpBackend *backend, const QByteArray &remote, qint64 size)
    : m_backend(backend), m_remote(remote), m_size(size)
{
    m_backend->registerHandle(this);
}

FtpReadHandle::~FtpReadHandle()
{
    close();
    if (m_backend)
        m_backend->unregisterHandle(this);
}

void FtpReadHandle::readAhead(qint64, qint64)
{
    // The running RETR already reads ahead; nothing to do.
}

Result FtpReadHandle::read(qint64 offset, qint64 maxBytes, QByteArray *out)
{
    if (out)
        out->clear();
    if (!m_valid)
        return lost();
    if (m_closed || offset < 0 || maxBytes < 0 || !out)
        return Result(Error::Internal, QStringLiteral("Invalid read"));
    if (maxBytes == 0 || (m_size >= 0 && offset >= m_size))
        return Result::success();
    const qint64 end = m_bufferStart + m_buffer.size();
    if (const bool continues = offset >= m_bufferStart && offset <= end && (m_streaming || m_eof || offset < end);
            !continues) {
        endStream();
        m_buffer.clear();
        m_bufferStart = offset;
        m_eof = false;
    } else {
        m_buffer.remove(0, int(offset - m_bufferStart));
        m_bufferStart = offset;
    }
    if (const Result r = fill(maxBytes); !r.ok())
        return r;
    const int take = int(std::min<qint64>(maxBytes, m_buffer.size()));
    *out = m_buffer.left(take);
    m_buffer.remove(0, take);
    m_bufferStart += take;
    return Result::success();
}

Result FtpReadHandle::startAt(qint64 offset)
{
    Result r = m_backend->claim(this);
    if (!r.ok())
        return r;
    Request request;
    request.kind = Request::Kind::Download;
    request.path = m_remote;
    request.offset = offset;
    request.commands = m_backend->prefixed({});
    r = m_backend->connection()->start(request, this);
    if (!r.ok()) {
        m_backend->release(this);
        return r;
    }
    m_streaming = true;
    return Result::success();
}

Result FtpReadHandle::fill(qint64 wanted)
{
    while (m_buffer.size() < wanted && !m_eof) {
        if (!m_streaming) {
            if (const Result r = startAt(m_bufferStart + m_buffer.size()); !r.ok())
                return r;
        }
        Result r = m_backend->claim(this);
        if (!r.ok())
            return r;
        m_wanted = wanted;
        Connection *connection = m_backend->connection();
        r = connection->pump([this, wanted] { return m_buffer.size() >= wanted; },
                             QStringLiteral("Reading"));
        if (connection->finished()) {
            m_streaming = false;
            m_backend->release(this);
            m_backend->requestDone();
            if (!r.ok())
                return FtpBackend::Lookup(*m_backend).readFailure(r, m_remote);
            m_eof = true;
        } else if (!r.ok()) {
            endStream();
            return r;
        }
    }
    return Result::success();
}

size_t FtpReadHandle::received(const char *data, size_t size)
{
    if (m_buffer.size() >= m_wanted)
        return CURL_WRITEFUNC_PAUSE;
    m_buffer.append(data, int(size));
    return size;
}

void FtpReadHandle::endStream()
{
    if (!m_streaming)
        return;
    m_streaming = false;
    if (m_backend && m_valid) {
        m_backend->connection()->stop();
        m_backend->release(this);
    }
}

Result FtpReadHandle::close()
{
    if (m_closed)
        return Result::success();
    endStream();
    m_closed = true;
    m_buffer.clear();
    return m_valid ? Result::success() : lost();
}

void FtpReadHandle::streamStopped()
{
    m_streaming = false;
}

void FtpReadHandle::invalidate()
{
    m_streaming = false;
    m_valid = false;
}

// --------------------------------------------------------------- write handle

FtpWriteHandle::FtpWriteHandle(FtpBackend *backend, const QByteArray &remote, const WriteOptions &options)
    : m_backend(backend), m_remote(remote), m_options(options)
{
    if (options.disposition == WriteOptions::Resume)
        m_position = options.resumeOffset;
    m_backend->registerHandle(this);
}

FtpWriteHandle::~FtpWriteHandle()
{
    if (!m_done)
        abort();
    if (m_backend)
        m_backend->unregisterHandle(this);
}

Result FtpWriteHandle::ensureStarted()
{
    Result r = m_backend->claim(this);
    if (!r.ok())
        return r;
    if (m_streaming)
        return Result::success();
    if (m_started) {
        // Another call on the backend needed the connection and ended the
        // upload; the server holds a partial file.
        return Result(Error::ConnectionLost, QStringLiteral("The upload was interrupted by another request"));
    }
    Request request;
    request.kind = Request::Kind::Upload;
    request.path = m_remote;
    request.append = m_options.disposition == WriteOptions::Resume;
    // No CURLOPT_INFILESIZE: libcurl would end the upload by itself once the
    // announced size went out; the upload ends with commit().
    request.commands = m_backend->prefixed({});
    r = m_backend->connection()->start(request, this);
    if (!r.ok()) {
        m_backend->release(this);
        return r;
    }
    m_started = true;
    m_streaming = true;
    return Result::success();
}

Result FtpWriteHandle::drive(bool toEnd)
{
    Connection *connection = m_backend->connection();
    Result r = connection->pump([this, toEnd] { return !toEnd && m_sent >= m_length; },
                                QStringLiteral("Uploading"));
    if (connection->finished()) {
        m_streaming = false;
        m_backend->release(this);
        m_backend->requestDone();
        if (!r.ok())
            return FtpBackend::Lookup(*m_backend).uploadFailure(r, m_remote);
        if (!toEnd)
            return Result(Error::ProtocolError, QStringLiteral("The server ended the upload early"));
        return r;
    }
    if (!r.ok()) {
        m_streaming = false;
        m_backend->release(this);
    }
    return r;
}

Result FtpWriteHandle::write(const char *data, qint64 length)
{
    if (!m_valid)
        return lost();
    if (!m_failure.ok())
        return m_failure;
    if (m_done || length < 0 || (length > 0 && !data))
        return Result(Error::Internal, QStringLiteral("Invalid write"));
    if (length == 0)
        return Result::success();
    Result r = ensureStarted();
    if (r.ok()) {
        m_data = data;
        m_length = length;
        m_sent = 0;
        r = drive(false);
        m_data = nullptr;
        m_length = 0;
    }
    if (!r.ok()) {
        m_failure = r;
        return r;
    }
    m_position += length;
    return Result::success();
}

Result FtpWriteHandle::commit()
{
    if (!m_valid)
        return lost();
    if (!m_failure.ok())
        return m_failure;
    if (m_done)
        return Result(Error::Internal, QStringLiteral("The upload is already finished"));
    Result r = ensureStarted();
    if (r.ok()) {
        m_eof = true;
        r = drive(true);
    }
    m_done = true;
    if (!r.ok()) {
        m_failure = r;
        return r;
    }
    if (m_options.modified.isValid())
        r = m_backend->applyModified(m_remote, m_options.modified);
    return r;
}

void FtpWriteHandle::abort()
{
    if (m_streaming && m_valid) {
        m_backend->connection()->stop();
        m_backend->release(this);
    }
    m_streaming = false;
    m_done = true;
}

size_t FtpWriteHandle::send(char *buffer, size_t size)
{
    const qint64 left = m_length - m_sent;
    if (left <= 0)
        return m_eof ? 0 : CURL_READFUNC_PAUSE;
    const qint64 n = std::min<qint64>(left, qint64(size));
    std::copy_n(m_data + m_sent, n, buffer);
    m_sent += n;
    return size_t(n);
}

void FtpWriteHandle::streamStopped()
{
    m_streaming = false;
}

void FtpWriteHandle::invalidate()
{
    m_streaming = false;
    m_valid = false;
}

} // namespace NetVfs::Ftp
