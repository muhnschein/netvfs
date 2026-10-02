// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DAVHANDLES_H
#define NETVFS_DAVHANDLES_H

#include "backend.h"
#include "davclient.h"

#include <memory>

// XC-13 handles of the WebDAV backend (W-9, W-10).
namespace NetVfs::WebDav {

class WebDavBackend;

// Shared between a backend and its handles; disconnect() clears `backend`
// so that later handle calls return ConnectionLost.
struct HandleLink {
    WebDavBackend *backend = nullptr;
};

class DavReadHandle final : public ReadHandle
{
public:
    DavReadHandle(std::shared_ptr<HandleLink> link, const QByteArray &url, qint64 size);
    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64, qint64) override
    {
        // Ranges are requested one by one; there is nothing to prefetch over HTTP.
    }
    Result close() override;

private:
    std::shared_ptr<HandleLink> m_link;
    QByteArray m_url;
    qint64 m_size;
    bool m_closed = false;
};

// `stream` null: the request is already complete (an empty file whose PUT
// was answered at open).
class DavWriteHandle final : public WriteHandle
{
public:
    DavWriteHandle(std::shared_ptr<HandleLink> link, std::unique_ptr<Client::Stream> stream,
                   const QString &path, const WriteOptions &options);
    ~DavWriteHandle() override;
    DavWriteHandle(const DavWriteHandle &) = delete;
    DavWriteHandle &operator=(const DavWriteHandle &) = delete;

    Result write(const char *data, qint64 length) override;
    qint64 position() const override { return m_position; }
    Result commit() override;
    void abort() override;

private:
    void release();

    std::shared_ptr<HandleLink> m_link;
    std::unique_ptr<Client::Stream> m_stream;
    QString m_path;
    WriteOptions m_options;
    qint64 m_position = 0;
    qint64 m_announced;          // Content-Length, -1 for chunked
    bool m_complete;
    bool m_released = false;
    Result m_failure;
};

} // namespace NetVfs::WebDav

#endif
