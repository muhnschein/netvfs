// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_WORKER_H
#define NETVFS_BRIDGE_WORKER_H

#include "args.h"
#include "backend.h"
#include "location.h"
#include "runtime.h"

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

namespace NetVfs::Bridge {

// Who a piece of work is for: the session (for questions) and the request's
// cancel token.
struct TaskContext {
    quint64 sessionId = 0;
    CancelTokenPtr token;
    bool canceled() const { return token && token->isCanceled(); }
};

// Opens a backend connection for a location on the calling worker thread:
// connect, identity check (XB-14), only then credentials and authenticate
// (C-7, XSEC-1). Implemented by the bridge; thread-safe.
class Connector
{
public:
    virtual ~Connector();
    virtual Result establish(Backend *backend, const LocationSpec &spec, const TaskContext &context) = 0;
};

// One backend connection on its own thread (C-8). Work items run in order.
// The backend is created and established lazily by the first item; an item
// that ends with Canceled, ConnectionLost or Timeout drops the connection
// (and the read handles on it), so the next item starts clean (XB-13).
class Worker
{
public:
    // `backend` is null when `ready` is an error (establish failed or the
    // item was canceled while queued). Returns the item's result.
    using Work = std::function<Result(Backend *backend, const Result &ready, Worker *worker)>;

    Worker(const LocationSpec &spec, Lane lane, Connector *connector);
    ~Worker();                         // stop() and join
    Worker(const Worker &) = delete;
    Worker &operator=(const Worker &) = delete;

    // Main thread.
    void post(const TaskContext &context, Work work);
    void kick();                       // cancels the running item if its token is set
    void stop();                       // non-blocking: cancel, drop the queue, end the thread
    bool finished() const { return m_finished.load(); }
    Lane lane() const { return m_lane; }
    int load() const;                  // queued + running items
    qint64 idleSinceMs() const;        // monotonic ms of the last activity, -1 while busy
    int openHandles() const { return m_handleCount.load(); }

    // Worker thread only (inside Work).
    quint32 addHandle(std::unique_ptr<ReadHandle> handle);
    ReadHandle *handle(quint32 id) const;
    void closeHandle(quint32 id);

private:
    struct Item {
        TaskContext context;
        Work work;
    };

    void run();
    Result ensureBackend(const TaskContext &context);
    void resetBackend();

    LocationSpec m_spec;
    Lane m_lane;
    Connector *m_connector;

    mutable std::mutex m_mutex;
    std::condition_variable m_cond;
    std::deque<Item> m_queue;
    bool m_stopping = false;
    bool m_running = false;
    CancelTokenPtr m_currentToken;
    std::unique_ptr<Backend> m_backend;   // created and deleted on the worker thread
    qint64 m_lastActivityMs = 0;

    std::map<quint32, std::unique_ptr<ReadHandle>> m_handles;   // worker thread
    quint32 m_nextHandle = 1;
    std::atomic<int> m_handleCount { 0 };
    std::atomic<bool> m_finished { false };
    std::thread m_thread;
};

} // namespace NetVfs::Bridge

#endif
