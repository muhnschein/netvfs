// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSHANDLES_H
#define NETVFS_RSHANDLES_H

// XC-13 handles of an RsBackend. Each owns its nvr_read / nvr_write until
// close, commit or abort, which free it (R4); deleting a handle still open
// closes (read) or aborts (write) it. As every handle, it is deleted before
// its backend.
#include "backend.h"
#include "netvfs_rs.h"

namespace NetVfs::Rs {

class RsReadHandle final : public ReadHandle
{
public:
    RsReadHandle(const nvr_table *table, nvr_read *handle, qint64 size) : m_t(table), m_h(handle), m_size(size) {}
    RsReadHandle(const RsReadHandle &) = delete;
    RsReadHandle &operator=(const RsReadHandle &) = delete;
    ~RsReadHandle() override;

    qint64 size() const override { return m_size; }
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64 offset, qint64 bytes) override;
    Result close() override;

private:
    const nvr_table *m_t;
    nvr_read *m_h;
    qint64 m_size;
};

class RsWriteHandle final : public WriteHandle
{
public:
    RsWriteHandle(const nvr_table *table, nvr_write *handle) : m_t(table), m_h(handle) {}
    RsWriteHandle(const RsWriteHandle &) = delete;
    RsWriteHandle &operator=(const RsWriteHandle &) = delete;
    ~RsWriteHandle() override;

    Result write(const char *data, qint64 length) override;
    qint64 position() const override;
    Result commit() override;
    void abort() override;

private:
    const nvr_table *m_t;
    nvr_write *m_h;
};

} // namespace NetVfs::Rs

#endif
