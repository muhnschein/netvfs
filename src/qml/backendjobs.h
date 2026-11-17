// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_BACKENDJOBS_H
#define NETVFS_QML_BACKENDJOBS_H

#include "backend.h"

#include <QtCore/QMutex>
#include <QtCore/QObject>
#include <QtCore/QThreadPool>

#include <atomic>
#include <functional>
#include <memory>

namespace NetVfsUi {

// Lets the UI thread cancel a blocking backend call running on a worker (Backend::cancel() is
// thread-safe).
class CancelToken
{
public:
    // The worker registers its backend for the duration of its calls. An already canceled token
    // cancels the backend at once.
    void attach(NetVfs::Backend *backend);
    void detach();
    void cancel();
    bool isCanceled() const { return m_canceled.load(); }

private:
    QMutex m_mutex;
    NetVfs::Backend *m_backend = nullptr;
    std::atomic<bool> m_canceled { false };
};

// Runs blocking work on a private thread pool, delivers completion on the owner's thread. Only the
// most recent job completes: a new job or cancel() discards the previous result. Destructor cancels
// and waits for running work.
class BackendJobs : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(BackendJobs)
public:
    explicit BackendJobs(QObject *parent = nullptr);
    ~BackendJobs() override;

    using Work = std::function<void(CancelToken *token)>;
    using Done = std::function<void()>;

    void start(const Work &work, const Done &done);
    void cancel();
    bool isRunning() const { return m_running; }

private:
    QThreadPool m_pool;
    std::shared_ptr<CancelToken> m_token;
    quint64 m_generation = 0;
    bool m_running = false;
};

}
#endif
