// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_NETWORKJOB_H
#define NETVFS_BUTEO_NETWORKJOB_H

#include "backend.h"

#include <QtCore/QMutex>
#include <QtCore/QThread>

#include <atomic>
#include <functional>

namespace NetVfs {

// One connection's worth of network work on its own thread (SPEC B-3, C-8).
// run() creates a fresh Backend, establishes the connection (identity check
// before authentication, SEC-1), wipes its copy of the credentials (SEC-5),
// runs the body and disconnects. The Backend never leaves that thread; only
// cancel() reaches it from outside. finished() is delivered to the thread
// that owns the job.
class NetworkJob : public QThread
{
    Q_OBJECT
public:
    using Body = std::function<Result(Backend *)>;

    NetworkJob(const QString &provider, const ConnectionParams &params, const Credentials &credentials,
               const Body &body, QObject *parent = nullptr);
    // Cancels and waits for the thread.
    ~NetworkJob() override;
    Q_DISABLE_COPY(NetworkJob)

    // Thread-safe; the in-flight call returns Canceled (C-9).
    void cancel();

    // Valid once the thread has finished.
    Result result() const { return m_result; }
    ServerIdentity seenIdentity() const { return m_seen; }

protected:
    void run() override;

private:
    void attach(Backend *backend);

    const QString m_provider;
    const ConnectionParams m_params;
    Credentials m_credentials;
    const Body m_body;

    QMutex m_mutex;                      // guards m_backend
    Backend *m_backend = nullptr;
    std::atomic<bool> m_canceled { false };

    Result m_result;
    ServerIdentity m_seen;
};

} // namespace NetVfs

#endif
