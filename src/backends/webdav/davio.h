// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVIO_H
#define NETVFS_DAVIO_H

#include "davclient.h"
#include "davxml.h"

#include <functional>

QT_BEGIN_NAMESPACE
class QIODevice;
QT_END_NAMESPACE

// Request bodies and response sinks of the WebDAV backend (W-7, W-9, W-10).
namespace NetVfs::WebDav {

// Upload body from a QIODevice; never reads past `size` (if known) and
// fails when the device ends before it. Reports progress as
// `progressBase + sent` of `progressTotal`.
class DeviceSource final : public BodySource
{
public:
    DeviceSource(QIODevice *device, qint64 size, Progress *progress, qint64 progressBase = 0,
                 qint64 progressTotal = -1);
    qint64 size() const override { return m_size; }
    qint64 read(char *buffer, qint64 maxSize) override;
    bool rewind() override;
    Result error() const override { return m_error; }
    qint64 sent() const { return m_sent; }

private:
    QIODevice *m_device;
    qint64 m_size;
    Progress *m_progress;
    qint64 m_progressBase;
    qint64 m_progressTotal;
    qint64 m_start;
    qint64 m_sent = 0;
    Result m_error;
};

// W-9: body of a GET that asked for bytes [offset, offset + length) (length
// -1: to the end). A 206 answer is taken as is (its Content-Range must start
// at `offset`); a 200 answer is the whole file, so `offset` bytes are
// skipped. Stops the transfer (on purpose) once `length` bytes are out.
class RangeSink final : public BodySink
{
public:
    using Output = std::function<bool(const char *data, qint64 size)>;
    RangeSink(const Response *response, qint64 offset, qint64 length, Output output,
              Progress *progress = nullptr, qint64 progressTotal = -1);
    bool write(const char *data, qint64 size) override;
    Result stopResult() const override { return m_error; }
    qint64 delivered() const { return m_delivered; }
    bool partial() const { return m_partial; }     // the server answered 206

private:
    bool start();

    const Response *m_response;
    qint64 m_offset;
    qint64 m_length;
    Output m_output;
    Progress *m_progress;
    qint64 m_progressTotal;
    bool m_started = false;
    bool m_partial = false;
    qint64 m_skip = 0;
    qint64 m_delivered = 0;
    Result m_error;
};

// Feeds a multistatus body into a parser while it streams (W-7).
class ParserSink final : public BodySink
{
public:
    explicit ParserSink(MultistatusParser *parser) : m_parser(parser) {}
    bool write(const char *data, qint64 size) override { return m_parser->feed(data, size); }
    Result stopResult() const override { return m_parser->result(); }

private:
    MultistatusParser *m_parser;
};

} // namespace NetVfs::WebDav

#endif
