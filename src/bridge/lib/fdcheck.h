// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_FDCHECK_H
#define NETVFS_BRIDGE_FDCHECK_H

#include "error.h"

#include <QtCore/QIODevice>

#include <atomic>

// SPEC-v2 XB-11: file descriptors passed by the consumer. The bridge never
// opens a local path; it only uses descriptors the consumer opened, checks
// them before any network work, reads and writes regular files with
// pread/pwrite at explicit offsets (the consumer's file offset is irrelevant),
// treats FIFOs as sequential streams, and never fsyncs, renames, truncates or
// deletes anything locally.
namespace NetVfs {
namespace Bridge {

enum class FdAccess { Read, Write };

struct FdInfo {
    bool fifo = false;                 // else a regular file
    qint64 size = -1;                  // regular file: st_size at check time
};

// PermissionDenied unless `fd` is a regular file or FIFO opened with the
// access mode `need` (O_RDONLY/O_RDWR to read, O_WRONLY/O_RDWR to write;
// O_PATH descriptors and, for writing, O_APPEND are refused because pwrite
// would ignore the offset).
Result checkTransferFd(int fd, FdAccess need, FdInfo *info);

// XB-11: a FIFO has no size, so an upload from one to a provider that must
// announce the length up front (WebDAV PUT with Content-Length) needs
// opts.size; otherwise Unsupported.
Result checkUploadLength(const FdInfo &info, qint64 size, const QString &provider);

// QIODevice over a checked descriptor (not owned; close() only stops using
// it). Regular files: random access within [offset, offset + length)
// mapped to device positions [0, length). FIFOs: sequential; reads stop after
// `length` bytes when length >= 0. Every blocking wait polls at most 200 ms
// at a time and gives up when `canceled` is set, so C-9 holds for local I/O.
class FdDevice : public QIODevice
{
public:
    FdDevice(int fd, const FdInfo &info, qint64 offset, qint64 length, const std::atomic<bool> *canceled);
    ~FdDevice() override;

    bool isSequential() const override;
    qint64 size() const override;
    bool seek(qint64 pos) override;
    void close() override;

    qint64 transferred() const { return m_transferred; }

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    bool waitFor(short events);
    bool canceled() const { return m_canceled && m_canceled->load(); }

    int m_fd;
    FdInfo m_info;
    qint64 m_offset;
    qint64 m_length;
    qint64 m_streamPos = 0;            // FIFO bytes consumed or produced
    qint64 m_transferred = 0;
    const std::atomic<bool> *m_canceled;
};

} // namespace Bridge
} // namespace NetVfs

#endif
