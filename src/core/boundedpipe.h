// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BOUNDEDPIPE_H
#define NETVFS_BOUNDEDPIPE_H

#include "error.h"

#include <QtCore/QIODevice>

#include <memory>

namespace NetVfs {

// SPEC-v2 XH-4: a pair of QIODevices over a ring buffer of fixed capacity,
// for streaming from one backend to another on two threads in constant
// memory. Reads block until data, EOF (writer closed) or failure; writes
// block until space. fail(result) on either side wakes both and makes every
// later read/write return -1 with that result in result(). cancel() is
// fail(Canceled). Both devices are opened by the constructor.
class NETVFS_EXPORT BoundedPipe
{
public:
    explicit BoundedPipe(qint64 capacity = 4 << 20);
    ~BoundedPipe();
    BoundedPipe(const BoundedPipe &) = delete;
    BoundedPipe &operator=(const BoundedPipe &) = delete;

    QIODevice *writer();   // write side; close() signals EOF
    QIODevice *reader();   // read side; returns 0 at EOF

    void fail(const Result &result);
    void cancel();
    Result result() const;     // success until fail()/cancel()
    qint64 capacity() const;
    qint64 buffered() const;   // bytes currently held

    struct State;

private:
    std::shared_ptr<State> m_state;
    std::unique_ptr<QIODevice> m_writer;
    std::unique_ptr<QIODevice> m_reader;
};

} // namespace NetVfs

#endif
