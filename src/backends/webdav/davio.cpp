// SPDX-License-Identifier: LGPL-2.1-or-later
#include "davio.h"
#include "davstatus.h"

#include <QtCore/QIODevice>

namespace NetVfs::WebDav {

namespace {
constexpr int StatusPartialContent = 206;
}

DeviceSource::DeviceSource(QIODevice *device, qint64 size, Progress *progress, qint64 progressBase,
                           qint64 progressTotal)
    : m_device(device)
    , m_size(size)
    , m_progress(progress)
    , m_progressBase(progressBase)
    , m_progressTotal(progressTotal)
    , m_start(device && !device->isSequential() ? device->pos() : 0)
{
}

qint64 DeviceSource::read(char *buffer, qint64 maxSize)
{
    qint64 want = maxSize;
    if (m_size >= 0)
        want = qMin(want, m_size - m_sent);
    if (want <= 0)
        return 0;
    const qint64 got = m_device->read(buffer, want);
    if (got < 0) {
        m_error = Result(Error::Internal, QStringLiteral("Cannot read the data to upload"));
        return Failed;
    }
    if (got == 0 && m_size >= 0) {
        m_error = Result(Error::Internal, QStringLiteral("The data to upload ended after %1 of %2 bytes")
                                              .arg(m_sent)
                                              .arg(m_size));
        return Failed;
    }
    m_sent += got;
    if (m_progress)
        m_progress->update(m_progressBase + m_sent, m_progressTotal);
    return got;
}

bool DeviceSource::rewind()
{
    if (m_sent == 0)
        return true;
    if (m_device->isSequential() || !m_device->seek(m_start))
        return false;
    m_sent = 0;
    return true;
}

RangeSink::RangeSink(const Response *response, qint64 offset, qint64 length, Output output,
                     Progress *progress, qint64 progressTotal)
    : m_response(response)
    , m_offset(offset)
    , m_length(length)
    , m_output(std::move(output))
    , m_progress(progress)
    , m_progressTotal(progressTotal)
{
}

bool RangeSink::start()
{
    m_started = true;
    m_partial = m_response->status == StatusPartialContent;
    if (!m_partial) {
        m_skip = m_offset;
        return true;
    }
    if (contentRangeStart(m_response->header("content-range")) != m_offset) {
        m_error = Result(Error::ProtocolError, QStringLiteral("The server sent a different range than requested"),
                         QString::fromLatin1(m_response->header("content-range")));
        return false;
    }
    return true;
}

bool RangeSink::write(const char *data, qint64 size)
{
    if (!m_started && !start())
        return false;
    if (m_progress && m_progress->canceled()) {
        m_error = Result(Error::Canceled, QStringLiteral("Canceled"));
        return false;
    }
    const qint64 skipped = qMin(m_skip, size);
    m_skip -= skipped;
    qint64 take = size - skipped;
    if (m_length >= 0)
        take = qMin(take, m_length - m_delivered);
    if (take > 0) {
        if (!m_output(data + skipped, take)) {
            m_error = Result(Error::Internal, QStringLiteral("Cannot store the downloaded data"));
            return false;
        }
        m_delivered += take;
        if (m_progress)
            m_progress->update(m_delivered, m_progressTotal);
    }
    // A whole-file answer is stopped (on purpose; m_error stays success)
    // once the range is out; a 206 ends by itself and keeps the connection.
    return m_partial || m_length < 0 || m_delivered < m_length;
}

} // namespace NetVfs::WebDav
