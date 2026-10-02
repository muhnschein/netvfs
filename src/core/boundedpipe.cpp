// SPDX-License-Identifier: LGPL-2.1-or-later
#include "boundedpipe.h"

#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QWaitCondition>

#include <algorithm>

namespace NetVfs {

// Shared between the two devices and the BoundedPipe; the devices keep it
// alive, so a device may outlive the BoundedPipe object without dangling.
struct BoundedPipe::State
{
    explicit State(qint64 size) : buffer(int(std::max<qint64>(size, 1)), Qt::Uninitialized) {}

    mutable QMutex mutex;
    QWaitCondition notEmpty;     // data arrived, writer closed or pipe failed
    QWaitCondition notFull;      // space freed or pipe failed
    QByteArray buffer;           // ring storage, fixed size
    qint64 head = 0;             // read position
    qint64 count = 0;            // bytes held
    qint64 peak = 0;
    bool writerClosed = false;
    bool readerClosed = false;
    Result failure;              // first fail() wins

    qint64 capacity() const { return buffer.size(); }

    bool failedLocked() const { return !failure.ok(); }

    void failLocked(const Result &result)
    {
        if (failure.ok())
            failure = result.ok() ? Result(Error::Internal, QStringLiteral("Pipe failed")) : result;
        notEmpty.wakeAll();
        notFull.wakeAll();
    }

    // Called with the mutex held; `maxSize` > 0. Returns the bytes copied out.
    qint64 takeLocked(char *data, qint64 maxSize)
    {
        const qint64 n = std::min(maxSize, count);
        const qint64 first = std::min(n, capacity() - head);
        std::copy_n(buffer.constData() + head, first, data);
        std::copy_n(buffer.constData(), n - first, data + first);
        head = (head + n) % capacity();
        count -= n;
        notFull.wakeAll();
        return n;
    }

    // Called with the mutex held; `length` > 0. Returns the bytes copied in.
    qint64 putLocked(const char *data, qint64 length)
    {
        const qint64 n = std::min(length, capacity() - count);
        const qint64 tail = (head + count) % capacity();
        const qint64 first = std::min(n, capacity() - tail);
        std::copy_n(data, first, buffer.data() + tail);
        std::copy_n(data + first, n - first, buffer.data());
        count += n;
        peak = std::max(peak, count);
        notEmpty.wakeAll();
        return n;
    }
};

namespace {

using State = BoundedPipe::State;

class PipeWriter : public QIODevice
{
public:
    explicit PipeWriter(std::shared_ptr<State> state) : m_state(std::move(state))
    {
        open(QIODevice::WriteOnly | QIODevice::Unbuffered);
    }
    ~PipeWriter() override { close(); }

    bool isSequential() const override { return true; }

    // EOF for the reader. Closing after fail() keeps the failure.
    void close() override
    {
        if (isOpen()) {
            QMutexLocker lock(&m_state->mutex);
            m_state->writerClosed = true;
            m_state->notEmpty.wakeAll();
        }
        QIODevice::close();
    }

protected:
    qint64 readData(char *, qint64) override { return -1; }

    // Blocks until all of `length` bytes are in the ring (bounded memory).
    qint64 writeData(const char *data, qint64 length) override
    {
        QMutexLocker lock(&m_state->mutex);
        qint64 done = 0;
        while (done < length) {
            while (m_state->count == m_state->capacity() && !m_state->failedLocked() && !m_state->readerClosed)
                m_state->notFull.wait(&m_state->mutex);
            if (!m_state->failedLocked() && m_state->readerClosed) {
                m_state->failLocked(Result(Error::Canceled, QStringLiteral("The pipe reader was closed")));
            }
            if (m_state->failedLocked()) {
                setErrorString(m_state->failure.message());
                return -1;
            }
            done += m_state->putLocked(data + done, length - done);
        }
        return length;
    }

private:
    std::shared_ptr<State> m_state;
};

class PipeReader : public QIODevice
{
public:
    explicit PipeReader(std::shared_ptr<State> state) : m_state(std::move(state))
    {
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
    }
    ~PipeReader() override { close(); }

    bool isSequential() const override { return true; }

    // Closing early tells a blocked writer that nobody will read.
    void close() override
    {
        if (isOpen()) {
            QMutexLocker lock(&m_state->mutex);
            m_state->readerClosed = true;
            m_state->notFull.wakeAll();
        }
        QIODevice::close();
    }

    qint64 bytesAvailable() const override
    {
        QMutexLocker lock(&m_state->mutex);
        return m_state->failedLocked() ? 0 : m_state->count + QIODevice::bytesAvailable();
    }

    // True only at EOF or after a failure: waits while the writer may still
    // deliver data, so that "while (!atEnd())" loops behave on a live pipe.
    bool atEnd() const override
    {
        QMutexLocker lock(&m_state->mutex);
        waitForDataLocked();
        return m_state->failedLocked() || m_state->count == 0;
    }

protected:
    // Returns what is available (at least one byte), 0 at EOF, -1 on failure.
    qint64 readData(char *data, qint64 maxSize) override
    {
        if (maxSize <= 0)
            return 0;
        QMutexLocker lock(&m_state->mutex);
        waitForDataLocked();
        if (m_state->failedLocked()) {
            setErrorString(m_state->failure.message());
            return -1;
        }
        if (m_state->count == 0)
            return 0;
        return m_state->takeLocked(data, maxSize);
    }
    qint64 writeData(const char *, qint64) override { return -1; }

private:
    void waitForDataLocked() const
    {
        while (m_state->count == 0 && !m_state->writerClosed && !m_state->failedLocked())
            m_state->notEmpty.wait(&m_state->mutex);
    }

    std::shared_ptr<State> m_state;
};

} // namespace

BoundedPipe::BoundedPipe(qint64 capacity)
    : m_state(std::make_shared<State>(capacity))
    , m_writer(new PipeWriter(m_state))
    , m_reader(new PipeReader(m_state))
{
}

BoundedPipe::~BoundedPipe()
{
    // Wakes a thread that is still blocked on one of the devices.
    cancel();
}

QIODevice *BoundedPipe::writer()
{
    return m_writer.get();
}

QIODevice *BoundedPipe::reader()
{
    return m_reader.get();
}

void BoundedPipe::fail(const Result &result)
{
    QMutexLocker lock(&m_state->mutex);
    m_state->failLocked(result);
}

void BoundedPipe::cancel()
{
    fail(Result(Error::Canceled));
}

Result BoundedPipe::result() const
{
    QMutexLocker lock(&m_state->mutex);
    return m_state->failure;
}

qint64 BoundedPipe::capacity() const
{
    return m_state->capacity();
}

qint64 BoundedPipe::buffered() const
{
    QMutexLocker lock(&m_state->mutex);
    return m_state->count;
}

qint64 BoundedPipe::peakBuffered() const
{
    QMutexLocker lock(&m_state->mutex);
    return m_state->peak;
}

} // namespace NetVfs
