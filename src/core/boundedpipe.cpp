// SPDX-License-Identifier: LGPL-2.1-or-later
#include "boundedpipe.h"

#include <algorithm>
#include <condition_variable>
#include <mutex>

namespace NetVfs {

// Shared between the two devices and the BoundedPipe; the devices keep it
// alive, so a device may outlive the BoundedPipe object without dangling.
// std::mutex and std::condition_variable rather than QMutex/QWaitCondition:
// ThreadSanitizer understands pthread synchronisation, but the atomics inside
// an uninstrumented Qt are invisible to it and would be reported as races.
struct BoundedPipe::State
{
    using Lock = std::unique_lock<std::mutex>;

    explicit State(qint64 size) : buffer(int(std::max<qint64>(size, 1)), Qt::Uninitialized) {}

    std::condition_variable notEmpty;   // data arrived, writer closed or pipe failed
    std::condition_variable notFull;    // space freed, reader closed or pipe failed
    QByteArray buffer;                  // ring storage, fixed size
    qint64 head = 0;                    // read position
    qint64 count = 0;                   // bytes held
    qint64 peak = 0;
    bool writerClosed = false;
    bool readerClosed = false;
    Result failure;                     // first fail() wins

    // The only way to the mutex: callers hold the returned lock while they use the state.
    Lock lock() const { return Lock(m_mutex); }

    qint64 capacity() const { return buffer.size(); }

    bool failedLocked() const { return !failure.ok(); }

    void failLocked(const Result &result)
    {
        if (failure.ok())
            failure = result.ok() ? Result(Error::Internal, QStringLiteral("Pipe failed")) : result;
        notEmpty.notify_all();
        notFull.notify_all();
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
        notFull.notify_all();
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
        notEmpty.notify_all();
        return n;
    }

    // Waits while the reader has nothing to take and nothing can arrive.
    void waitForDataLocked(Lock *lock)
    {
        notEmpty.wait(*lock, [this] { return count > 0 || writerClosed || failedLocked(); });
    }

    // Waits while the ring is full and the writer may still be served.
    void waitForSpaceLocked(Lock *lock)
    {
        notFull.wait(*lock, [this] { return count < capacity() || failedLocked() || readerClosed; });
    }

private:
    mutable std::mutex m_mutex;
};

namespace {

using State = BoundedPipe::State;

class PipeWriter final : public QIODevice
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
            State::Lock lock = m_state->lock();
            m_state->writerClosed = true;
            m_state->notEmpty.notify_all();
        }
        QIODevice::close();
    }

protected:
    qint64 readData(char *, qint64) override { return -1; }

    // Blocks until all of `length` bytes are in the ring (bounded memory).
    qint64 writeData(const char *data, qint64 length) override
    {
        State::Lock lock = m_state->lock();
        qint64 done = 0;
        while (done < length) {
            m_state->waitForSpaceLocked(&lock);
            if (!m_state->failedLocked() && m_state->readerClosed)
                m_state->failLocked(Result(Error::Canceled, QStringLiteral("The pipe reader was closed")));
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

class PipeReader final : public QIODevice
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
            State::Lock lock = m_state->lock();
            m_state->readerClosed = true;
            m_state->notFull.notify_all();
        }
        QIODevice::close();
    }

    qint64 bytesAvailable() const override
    {
        State::Lock lock = m_state->lock();
        return m_state->failedLocked() ? 0 : m_state->count + QIODevice::bytesAvailable();
    }

    // True only at EOF or after a failure: waits while the writer may still
    // deliver data, so that "while (!atEnd())" loops behave on a live pipe.
    bool atEnd() const override
    {
        State::Lock lock = m_state->lock();
        m_state->waitForDataLocked(&lock);
        return m_state->failedLocked() || m_state->count == 0;
    }

protected:
    // Returns what is available (at least one byte), 0 at EOF, -1 on failure.
    qint64 readData(char *data, qint64 maxSize) override
    {
        if (maxSize <= 0)
            return 0;
        State::Lock lock = m_state->lock();
        m_state->waitForDataLocked(&lock);
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
    std::shared_ptr<State> m_state;
};

} // namespace

BoundedPipe::BoundedPipe(qint64 capacity)
    : m_state(std::make_shared<State>(capacity))
    , m_writer(std::make_unique<PipeWriter>(m_state))
    , m_reader(std::make_unique<PipeReader>(m_state))
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

void BoundedPipe::fail(const Result &result) const
{
    State::Lock lock = m_state->lock();
    m_state->failLocked(result);
}

void BoundedPipe::cancel() const
{
    fail(Result(Error::Canceled));
}

Result BoundedPipe::result() const
{
    State::Lock lock = m_state->lock();
    return m_state->failure;
}

qint64 BoundedPipe::capacity() const
{
    return m_state->capacity();
}

qint64 BoundedPipe::buffered() const
{
    State::Lock lock = m_state->lock();
    return m_state->count;
}

qint64 BoundedPipe::peakBuffered() const
{
    State::Lock lock = m_state->lock();
    return m_state->peak;
}

} // namespace NetVfs
