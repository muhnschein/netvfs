// SPDX-License-Identifier: LGPL-2.1-or-later
#include "pool.h"

#include <algorithm>

namespace NetVfs {
namespace Bridge {

int PoolLimits::forLane(Lane lane)
{
    switch (lane) {
    case Lane::Bulk:
        return Bulk;
    case Lane::Stream:
        return Stream;
    case Lane::Interactive:
        break;
    }
    return Interactive;
}

// ----------------------------------------------------------- HostRegistry

bool HostRegistry::tryAcquire(const QString &host, int count)
{
    int &used = m_used[host];
    if (used + count > m_perHost)
        return false;
    used += count;
    return true;
}

void HostRegistry::release(const QString &host, int count)
{
    auto it = m_used.find(host);
    if (it == m_used.end())
        return;
    it.value() = std::max(0, it.value() - count);
    if (it.value() == 0)
        m_used.erase(it);
}

bool HostRegistry::evictIdle(const QString &host, const Pool *except)
{
    for (Pool *pool : m_pools) {
        if (pool != except && pool->spec().hostKey() == host && pool->closeOneIdle())
            return true;
    }
    return false;
}

void HostRegistry::notifyReleased(const QString &host)
{
    const QList<Pool *> pools = m_pools;
    for (Pool *pool : pools) {
        if (pool->spec().hostKey() == host)
            pool->retryPending();
    }
}

// ------------------------------------------------------------------- Pool

Pool::Pool(const LocationSpec &spec, Connector *connector, HostRegistry *hosts)
    : m_spec(spec)
    , m_connector(connector)
    , m_hosts(hosts)
{
    m_hosts->addPool(this);
}

Pool::~Pool()
{
    m_hosts->removePool(this);
    stopAll();
    for (auto &worker : m_retired)
        worker.reset();   // joins
    m_hosts->release(m_spec.hostKey(), static_cast<int>(m_retired.size()));
    m_retired.clear();
    for (Pending &pending : m_pending)
        pending.work(nullptr, Result(Error::Canceled), nullptr);
    m_pending.clear();
}

bool Pool::owns(const Worker *worker) const
{
    return std::any_of(m_workers.cbegin(), m_workers.cend(),
                       [worker](const std::unique_ptr<Worker> &w) { return w.get() == worker; });
}

Worker *Pool::leastLoaded(Lane lane, bool anyLane) const
{
    Worker *best = nullptr;
    int bestLoad = 0;
    for (const auto &worker : m_workers) {
        if (!anyLane && worker->lane() != lane)
            continue;
        const int load = worker->load();
        if (!best || load < bestLoad) {
            best = worker.get();
            bestLoad = load;
        }
    }
    return best;
}

Worker *Pool::pick(Lane lane)
{
    Worker *existing = leastLoaded(lane, false);
    if (existing && existing->load() == 0)
        return existing;
    const auto inLane = std::count_if(m_workers.cbegin(), m_workers.cend(),
                                      [lane](const std::unique_ptr<Worker> &w) { return w->lane() == lane; });
    const QString host = m_spec.hostKey();
    if (inLane < PoolLimits::forLane(lane)
            && (m_hosts->tryAcquire(host) || (m_hosts->evictIdle(host, this) && m_hosts->tryAcquire(host)))) {
        m_workers.push_back(std::make_unique<Worker>(m_spec, lane, m_connector));
        return m_workers.back().get();
    }
    if (existing)
        return existing;
    // No connection of this lane and the host is full: borrow another lane's.
    return leastLoaded(lane, true);
}

void Pool::submit(Lane lane, const TaskContext &context, Worker::Work work)
{
    Worker *worker = pick(lane);
    if (!worker) {
        m_pending.push_back(Pending { lane, context, std::move(work) });
        return;
    }
    worker->post(context, std::move(work));
}

void Pool::submitTo(Worker *worker, const TaskContext &context, Worker::Work work)
{
    worker->post(context, std::move(work));
}

void Pool::retryPending()
{
    std::vector<Pending> pending;
    pending.swap(m_pending);
    for (Pending &p : pending)
        submit(p.lane, p.context, std::move(p.work));
}

void Pool::kick()
{
    for (const auto &worker : m_workers)
        worker->kick();
    // Canceled work that never got a connection ends now.
    std::vector<Pending> keep;
    for (Pending &p : m_pending) {
        if (p.context.canceled())
            p.work(nullptr, Result(Error::Canceled), nullptr);
        else
            keep.push_back(std::move(p));
    }
    m_pending.swap(keep);
}

void Pool::retire(std::vector<std::unique_ptr<Worker>>::iterator it)
{
    (*it)->stop();
    m_retired.push_back(std::move(*it));
    m_workers.erase(it);
}

void Pool::stopAll()
{
    while (!m_workers.empty())
        retire(m_workers.begin());
}

bool Pool::closeOneIdle()
{
    const auto it = std::find_if(m_workers.begin(), m_workers.end(), [](const std::unique_ptr<Worker> &w) {
        return w->idleSinceMs() >= 0 && w->openHandles() == 0;
    });
    if (it == m_workers.end())
        return false;
    retire(it);
    reapFinished();
    // The slot frees when the thread has finished; count it free now, the
    // connection is already being closed.
    if (!m_retired.empty()) {
        m_retired.back().reset();
        m_retired.pop_back();
        m_hosts->release(m_spec.hostKey());
    }
    return true;
}

void Pool::reapFinished()
{
    const QString host = m_spec.hostKey();
    int released = 0;
    for (auto it = m_retired.begin(); it != m_retired.end();) {
        if ((*it)->finished()) {
            it->reset();
            it = m_retired.erase(it);
            ++released;
        } else {
            ++it;
        }
    }
    if (released > 0) {
        m_hosts->release(host, released);
        m_hosts->notifyReleased(host);
    }
}

bool Pool::maintain(qint64 nowMs, qint64 idleMs)
{
    bool changed = false;
    for (auto it = m_workers.begin(); it != m_workers.end();) {
        const qint64 since = (*it)->idleSinceMs();
        if (since >= 0 && nowMs - since >= idleMs && (*it)->openHandles() == 0) {
            const auto index = it - m_workers.begin();
            retire(it);
            it = m_workers.begin() + index;
            changed = true;
        } else {
            ++it;
        }
    }
    const size_t before = m_retired.size();
    reapFinished();
    return changed || before != m_retired.size();
}

bool Pool::isIdle() const
{
    return m_pending.empty() && std::all_of(m_workers.cbegin(), m_workers.cend(), [](const std::unique_ptr<Worker> &w) {
        return w->idleSinceMs() >= 0;
    });
}

} // namespace Bridge
} // namespace NetVfs
