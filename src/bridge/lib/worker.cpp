// SPDX-License-Identifier: LGPL-2.1-or-later
#include "worker.h"

#include "backendloader.h"
#include "bridgelog.h"

#include <chrono>

namespace NetVfs {
namespace Bridge {

namespace {

qint64 monotonicMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

bool dropsConnection(const Result &result)
{
    switch (result.error()) {
    case Error::Canceled:
    case Error::ConnectionLost:
    case Error::Timeout:
    case Error::NetworkUnreachable:
        return true;
    default:
        return false;
    }
}

} // namespace

Connector::~Connector() = default;

Worker::Worker(const LocationSpec &spec, Lane lane, Connector *connector)
    : m_spec(spec)
    , m_lane(lane)
    , m_connector(connector)
    , m_lastActivityMs(monotonicMs())
{
    m_thread = std::thread([this]() { run(); });
}

Worker::~Worker()
{
    stop();
    if (m_thread.joinable())
        m_thread.join();
}

void Worker::post(const TaskContext &context, Work work)
{
    // Also queued while stopping: run() hands it Canceled, so it is never lost.
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push_back(Item { context, std::move(work) });
    m_cond.notify_all();
}

void Worker::kick()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_currentToken && m_currentToken->isCanceled() && m_backend)
        m_backend->cancel();
}

void Worker::stop()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stopping = true;
    if (m_currentToken)
        m_currentToken->cancel();
    if (m_backend)
        m_backend->cancel();
    m_cond.notify_all();
}

int Worker::load() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_queue.size()) + (m_running ? 1 : 0);
}

qint64 Worker::idleSinceMs() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running || !m_queue.empty())
        return -1;
    return m_lastActivityMs;
}

quint32 Worker::addHandle(ReadHandle *handle)
{
    const quint32 id = m_nextHandle++;
    m_handles.insert(id, handle);
    m_handleCount.store(m_handles.size());
    return id;
}

ReadHandle *Worker::handle(quint32 id) const
{
    return m_handles.value(id, nullptr);
}

void Worker::closeHandle(quint32 id)
{
    ReadHandle *handle = m_handles.take(id);
    if (handle) {
        handle->close();
        delete handle;
    }
    m_handleCount.store(m_handles.size());
}

Result Worker::ensureBackend(const TaskContext &context)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_backend)
            return Result::success();
    }
    Result created;
    Backend *backend = BackendLoader::create(m_spec.provider, &created);
    if (!backend)
        return created.ok() ? Result(Error::Unsupported, QStringLiteral("No backend for this location")) : created;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_backend = backend;
        if (m_stopping || context.canceled())
            backend->cancel();
    }
    const Result r = m_connector->establish(backend, m_spec, context);
    if (!r.ok())
        resetBackend();
    return r;
}

void Worker::resetBackend()
{
    // Handles must go before their backend (backend.h).
    for (auto it = m_handles.begin(); it != m_handles.end(); ++it)
        delete it.value();
    m_handles.clear();
    m_handleCount.store(0);
    Backend *backend = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        backend = m_backend;
        m_backend = nullptr;
    }
    if (backend) {
        backend->disconnect();
        delete backend;
    }
}

void Worker::run()
{
    for (;;) {
        Item item;
        bool stopping = false;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cond.wait(lock, [this]() { return m_stopping || !m_queue.empty(); });
            stopping = m_stopping;
            if (m_queue.empty())
                break;
            item = std::move(m_queue.front());
            m_queue.pop_front();
            m_running = true;
            m_currentToken = item.context.token;
        }
        Result ready;
        if (stopping || item.context.canceled())
            ready = Result(Error::Canceled);
        else
            ready = ensureBackend(item.context);
        Backend *backend = nullptr;
        if (ready.ok()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            backend = m_backend;
        }
        const Result result = item.work(ready.ok() ? backend : nullptr, ready, this);
        if (ready.ok() && (dropsConnection(result) || item.context.canceled()))
            resetBackend();
        else if (backend)
            backend->resetCancel();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running = false;
        m_currentToken.reset();
        m_lastActivityMs = monotonicMs();
    }
    resetBackend();
    m_finished.store(true);
}

} // namespace Bridge
} // namespace NetVfs
