// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_POOL_H
#define NETVFS_BRIDGE_POOL_H

#include "worker.h"

#include <QtCore/QHash>
#include <QtCore/QList>

#include <memory>
#include <vector>

// SPEC-v2 XB-12: connection pools per location, with lanes as the consumer
// hints them: interactive 1, bulk 2, stream 1 connection, and at most 4
// connections per host across all locations of the consumer.
namespace NetVfs {
namespace Bridge {

class Pool;

namespace PoolLimits {
constexpr int Interactive = 1;
constexpr int Bulk = 2;
constexpr int Stream = 1;
constexpr int PerHost = 4;
int forLane(Lane lane);
} // namespace PoolLimits

// Connection counts per host (main thread). Stopped workers count until
// their thread has finished.
class HostRegistry
{
public:
    explicit HostRegistry(int perHost = PoolLimits::PerHost) : m_perHost(perHost) {}

    bool tryAcquire(const QString &host, int count = 1);
    void release(const QString &host, int count = 1);
    int inUse(const QString &host) const { return m_used.value(host); }
    int perHost() const { return m_perHost; }

    void addPool(Pool *pool) { m_pools.append(pool); }
    void removePool(Pool *pool) { m_pools.removeAll(pool); }
    // Frees a slot on `host` by closing an idle connection of another pool.
    bool evictIdle(const QString &host, const Pool *except);
    // A slot came free: pools with waiting work retry.
    void notifyReleased(const QString &host);

private:
    int m_perHost;
    QHash<QString, int> m_used;
    QList<Pool *> m_pools;
};

class Pool
{
public:
    Pool(const LocationSpec &spec, Connector *connector, HostRegistry *hosts);
    ~Pool();                           // stops and joins every worker
    Pool(const Pool &) = delete;
    Pool &operator=(const Pool &) = delete;

    const LocationSpec &spec() const { return m_spec; }
    void setSpec(const LocationSpec &spec) { m_spec = spec; }

    // Queues work on a connection of `lane` (main thread).
    void submit(Lane lane, const TaskContext &context, Worker::Work work);
    // Queues work on one specific connection (read handles live there).
    static void submitTo(Worker *worker, const TaskContext &context, Worker::Work work);
    bool owns(const Worker *worker) const;

    void kick();                       // after tokens were canceled
    void stopAll();                    // Disconnect, ForgetAdHoc, revocation
    // Stops connections idle for `idleMs` without open handles; joins
    // finished ones. Returns true if anything changed.
    bool maintain(qint64 nowMs, qint64 idleMs);
    bool closeOneIdle();
    void retryPending();
    bool isIdle() const;
    int connectionCount() const { return static_cast<int>(m_workers.size()); }

private:
    struct Pending {
        Lane lane;
        TaskContext context;
        Worker::Work work;
    };

    Worker *pick(Lane lane);
    Worker *leastLoaded(Lane lane, bool anyLane) const;
    void retire(std::vector<std::unique_ptr<Worker>>::iterator it);
    void reapFinished();

    LocationSpec m_spec;
    Connector *m_connector;
    HostRegistry *m_hosts;
    std::vector<std::unique_ptr<Worker>> m_workers;
    std::vector<std::unique_ptr<Worker>> m_retired;   // stopping, joined when finished
    std::vector<Pending> m_pending;
};

} // namespace Bridge
} // namespace NetVfs

#endif
