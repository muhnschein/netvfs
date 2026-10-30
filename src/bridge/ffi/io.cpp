// SPDX-License-Identifier: LGPL-2.1-or-later
// Upload and Download: the backend streams through a QIODevice whose local side is the caller's
// nvb_io. The caller checked the descriptor and does pread/pwrite (regular file) or read/write
// (FIFO). Random access within the range for regular files, sequential for FIFOs; every failure or
// cancel is -1.
#include "ffi_p.h"

#include <QtCore/QIODevice>

#include <algorithm>
#include <stdexcept>

namespace NetVfs::Ffi {

namespace {

class CallbackDevice final : public QIODevice
{
public:
    explicit CallbackDevice(const nvb_io &io) : m_io(io) {}

    bool isSequential() const override { return m_io.sequential != 0; }
    qint64 size() const override { return isSequential() ? 0 : m_io.size; }

    bool seek(qint64 pos) override
    {
        if (isSequential() || pos < 0)
            return false;
        return QIODevice::seek(pos);
    }

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    qint64 position() const { return isSequential() ? m_streamPos : pos(); }

    nvb_io m_io;
    qint64 m_streamPos = 0;
};

qint64 CallbackDevice::readData(char *data, qint64 maxSize)
{
    if (!m_io.read)
        return -1;
    const qint64 at = position();
    qint64 want = maxSize;
    if (!isSequential())
        want = std::min(want, m_io.size - at);
    if (want <= 0)
        return 0;
    const int64_t n = m_io.read(m_io.ctx, at, reinterpret_cast<uint8_t *>(data), static_cast<size_t>(want));
    if (n < 0 || n > want)
        return -1;
    m_streamPos += n;
    return n;
}

// FIFOs: one call, may be short. Regular files: until everything is written; a stop after some
// bytes reports those.
qint64 CallbackDevice::writeData(const char *data, qint64 maxSize)
{
    if (!m_io.write)
        return -1;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (isSequential()) {
        const int64_t n = m_io.write(m_io.ctx, m_streamPos, bytes, static_cast<size_t>(maxSize));
        if (n < 0 || n > maxSize)
            return -1;
        m_streamPos += n;
        return n;
    }
    qint64 written = 0;
    while (written < maxSize) {
        const int64_t n = m_io.write(m_io.ctx, pos() + written, bytes + written,
                                     static_cast<size_t>(maxSize - written));
        if (n <= 0 || n > maxSize - written)
            return written > 0 ? written : -1;
        written += n;
    }
    return written;
}

const nvb_io &ioOf(const nvb_io *io)
{
    if (!io)
        throw std::invalid_argument("no local side");
    return *io;
}

WriteOptions::Disposition dispositionOf(uint32_t disposition)
{
    switch (disposition) {
    case NVB_DISPOSITION_TRUNCATE:
        return WriteOptions::Disposition::Truncate;
    case NVB_DISPOSITION_RESUME:
        return WriteOptions::Disposition::Resume;
    default:
        return WriteOptions::Disposition::CreateNew;
    }
}

UploadOptions uploadOptionsOf(const nvb_upload_opts *opts)
{
    UploadOptions options;
    if (!opts)
        return options;
    options.write.disposition = dispositionOf(opts->disposition);
    options.write.createMode = opts->create_mode;
    options.write.resumeOffset = opts->resume_offset;
    options.write.expectedSize = opts->expected_size;
    if (opts->has_mtime)
        options.write.modified = fromMs(opts->mtime_ms);
    return options;
}

}
void ProgressAdapter::update(qint64 done, qint64 total)
{
    if (m_progress && m_progress->update)
        m_progress->update(m_progress->ctx, done, total);
}

bool ProgressAdapter::canceled() const
{
    return m_progress && m_progress->canceled && m_progress->canceled(m_progress->ctx) != 0;
}

bool ProgressAdapter::removed(const QString &, bool, qint64 files, qint64 dirs)
{
    update(files + dirs, -1);
    return !canceled();
}

nvb_error *connUpload(nvb_conn *conn, nvb_bytes path, const nvb_upload_opts *opts, const nvb_io *io,
                      const nvb_progress *progress) noexcept
{
    return guarded([conn, path, opts, io, progress]() {
        Backend *backend = backendOf(conn);
        CallbackDevice device(ioOf(io));
        device.open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        ProgressAdapter adapter(progress);
        return backend->upload(&device, toPath(path), uploadOptionsOf(opts), &adapter);
    });
}

nvb_error *connDownload(nvb_conn *conn, nvb_bytes path, int64_t offset, int64_t length, const nvb_io *io,
                        const nvb_progress *progress) noexcept
{
    return guarded([conn, path, offset, length, io, progress]() {
        Backend *backend = backendOf(conn);
        CallbackDevice device(ioOf(io));
        device.open(QIODevice::WriteOnly | QIODevice::Unbuffered);
        ProgressAdapter adapter(progress);
        DownloadOptions options;
        options.offset = offset;
        options.length = length;
        return backend->download(toPath(path), &device, options, &adapter);
    });
}

}