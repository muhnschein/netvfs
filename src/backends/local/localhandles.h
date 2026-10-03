// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_LOCALHANDLES_H
#define NETVFS_LOCALHANDLES_H

#include "localbackend.h"

namespace NetVfs::Local {

// XC-13 over one descriptor. Regular files are read with pread(); streams
// (FIFOs, devices) only sequentially, at the position reached so far.
class LocalReadHandle : public ReadHandle
{
public:
    LocalReadHandle(std::shared_ptr<Context> context, Fd fd, const NativeStat &st);

    qint64 size() const override;
    Result read(qint64 offset, qint64 maxBytes, QByteArray *out) override;
    void readAhead(qint64 offset, qint64 bytes) override;
    Result close() override;

private:
    Result check();

    std::shared_ptr<Context> m_context;
    quint64 m_generation;
    Fd m_fd;
    qint64 m_size;
    bool m_seekable;
    qint64 m_streamPosition = 0;
};

// XC-13 sequential writes. commit() is fsync + futimens (WriteOptions::
// modified) + close (L-7).
class LocalWriteHandle : public WriteHandle
{
public:
    LocalWriteHandle(std::shared_ptr<Context> context, Fd fd, qint64 position, const QDateTime &modified);

    Result write(const char *data, qint64 length) override;
    qint64 position() const override;
    Result commit() override;
    void abort() override;

private:
    Result check();

    std::shared_ptr<Context> m_context;
    quint64 m_generation;
    Fd m_fd;
    qint64 m_position;
    QDateTime m_modified;
};

} // namespace NetVfs::Local

#endif
