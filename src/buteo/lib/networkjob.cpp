// SPDX-License-Identifier: LGPL-2.1-or-later
#include "networkjob.h"
#include "backendloader.h"
#include "identity.h"

#include <QtCore/QMutexLocker>
#include <QtCore/QScopedPointer>

namespace NetVfs {

NetworkJob::NetworkJob(const QString &provider, const ConnectionParams &params,
                       const Credentials &credentials, const Body &body, QObject *parent)
    : QThread(parent)
    , m_provider(provider)
    , m_params(params)
    , m_credentials(credentials)
    , m_body(body)
{
}

NetworkJob::~NetworkJob()
{
    cancel();
    wait();
    m_credentials.wipe();
}

void NetworkJob::cancel()
{
    QMutexLocker lock(&m_mutex);
    m_canceled = true;
    if (m_backend)
        m_backend->cancel();
}

void NetworkJob::attach(Backend *backend)
{
    QMutexLocker lock(&m_mutex);
    m_backend = backend;
    if (m_backend && m_canceled)
        m_backend->cancel();
}

void NetworkJob::run()
{
    Result r;
    QScopedPointer<Backend> backend(BackendLoader::create(m_provider, &r));
    if (!backend) {
        m_credentials.wipe();
        m_result = r;
        return;
    }

    attach(backend.data());
    r = establish(backend.data(), m_params, m_credentials, &m_seen);
    m_credentials.wipe();
    if (r.ok()) {
        r = m_body(backend.data());
        backend->disconnect();
    }
    attach(nullptr);
    m_result = r;
}

} // namespace NetVfs
