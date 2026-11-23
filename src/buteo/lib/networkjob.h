// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_NETWORKJOB_H
#define NETVFS_BUTEO_NETWORKJOB_H

#include "backend.h"

#include <QtCore/QMutex>
#include <QtCore/QThread>

#include <atomic>
#include <functional>

namespace NetVfs {
class NetworkJob : public QThread
{
    Q_OBJECT
public:
    using Body = std::function<Result(Backend *)>;

    NetworkJob(const QString &provider, const ConnectionParams &params, const Credentials &credentials,
               const Body &body, QObject *parent = nullptr);
    ~NetworkJob() override;
    Q_DISABLE_COPY(NetworkJob)

    void cancel();

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

    QMutex m_mutex;
    Backend *m_backend = nullptr;
    std::atomic<bool> m_canceled { false };

    Result m_result;
    ServerIdentity m_seen;
};

}
#endif
