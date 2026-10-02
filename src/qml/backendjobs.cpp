// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backendjobs.h"

#include <QtConcurrent/QtConcurrentRun>
#include <QtCore/QFutureWatcher>
#include <QtCore/QMutexLocker>

using namespace NetVfs;

namespace NetVfsUi {

void CancelToken::attach(Backend *backend)
{
    QMutexLocker lock(&m_mutex);
    m_backend = backend;
    if (m_canceled.load() && m_backend)
        m_backend->cancel();
}

void CancelToken::detach()
{
    QMutexLocker lock(&m_mutex);
    m_backend = nullptr;
}

void CancelToken::cancel()
{
    QMutexLocker lock(&m_mutex);
    m_canceled.store(true);
    if (m_backend)
        m_backend->cancel();
}

BackendJobs::BackendJobs(QObject *parent)
    : QObject(parent)
{
}

BackendJobs::~BackendJobs()
{
    cancel();
    m_pool.waitForDone();
}

void BackendJobs::start(const Work &work, const Done &done)
{
    cancel();
    const quint64 generation = ++m_generation;
    const std::shared_ptr<CancelToken> token = std::make_shared<CancelToken>();
    m_token = token;
    m_running = true;

    auto owned = std::make_unique<QFutureWatcher<void>>();
    owned->setParent(this);
    QFutureWatcher<void> *watcher = owned.release();
    connect(watcher, &QFutureWatcherBase::finished, this, [this, watcher, generation, done]() {
        watcher->deleteLater();
        if (generation != m_generation)
            return;
        m_running = false;
        m_token.reset();
        done();
    });
    watcher->setFuture(QtConcurrent::run(&m_pool, [work, token]() { work(token.get()); }));
}

void BackendJobs::cancel()
{
    ++m_generation;
    m_running = false;
    if (m_token)
        m_token->cancel();
    m_token.reset();
}

} // namespace NetVfsUi
