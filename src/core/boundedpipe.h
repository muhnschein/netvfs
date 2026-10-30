// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BOUNDEDPIPE_H
#define NETVFS_BOUNDEDPIPE_H

#include "error.h"

#include <QtCore/QIODevice>

#include <memory>

namespace NetVfs {

// Two QIODevices over a fixed ring buffer: constant-memory streaming between backends on two
// threads. Reads block until data, EOF or failure; writes block until space. fail(result) wakes
// both; later read/write return -1 with result(). cancel() is fail(Canceled).
class NETVFS_EXPORT BoundedPipe
{
public:
    explicit BoundedPipe(qint64 capacity = 4 << 20);
    ~BoundedPipe();
    BoundedPipe(const BoundedPipe &) = delete;
    BoundedPipe &operator=(const BoundedPipe &) = delete;

    QIODevice *writer();
    QIODevice *reader();
    void fail(const Result &result) const;
    void cancel() const;
    Result result() const;
    qint64 capacity() const;
    qint64 buffered() const;
    qint64 peakBuffered() const;

    struct State;

private:
    std::shared_ptr<State> m_state;
    std::unique_ptr<QIODevice> m_writer;
    std::unique_ptr<QIODevice> m_reader;
};

}
#endif
