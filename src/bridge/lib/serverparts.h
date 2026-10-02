// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_SERVERPARTS_H
#define NETVFS_BRIDGE_SERVERPARTS_H

// The parts of a BridgeServer (SPEC-v2 XB-2): what one consumer may have in
// flight (XB-17), its locations with their connection pools (XB-7, XB-12),
// the copy jobs on threads of their own, and the discovery of nearby servers
// (XD-5). The server owns one of each and hands them to the sessions. Main
// thread only, except where noted. Included by .cpp files only (moc of Qt 5.6
// cannot read its C++17 nested namespace).
#include "bridgeserver.h"
#include "connector.h"
#include "discovery.h"
#include "pool.h"

#include <QtCore/QHash>
#include <QtCore/QTimer>
#include <QtCore/QVector>

#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace NetVfs::Bridge {

// XB-17: the requests, open files and jobs of the consumer. Every change
// re-evaluates the idle exit (XB-2).
class ConsumerQuota
{
public:
    explicit ConsumerQuota(BridgeServer *server) : m_server(server) {}

    bool acquireRequest();
    void releaseRequest();
    bool acquireHandle();
    void releaseHandle();
    bool acquireJob();
    void releaseJob();

    int activeRequests() const { return m_requests; }
    int openHandles() const { return m_handles; }
    int runningJobs() const { return m_jobs; }

private:
    BridgeServer *m_server;
    int m_requests = 0;
    int m_handles = 0;
    int m_jobs = 0;
};

// XB-7, XB-12, XB-14: the locations a consumer may see (accounts and the
// ad-hoc ones it created), their connection pools, and what the connections
// need: the host limits, the known hosts and the connector.
class LocationBook
{
public:
    LocationBook(BridgeServer *server, AccountDirectory *injectedAccounts);
    ~LocationBook();
    LocationBook(const LocationBook &) = delete;
    LocationBook &operator=(const LocationBook &) = delete;

    // Reads the accounts database (start()).
    void load();
    // The accounts changed: pools whose settings changed or whose account
    // went away are dropped (new connections use the new settings).
    void refresh();
    // Consent was revoked (XB-6): pools and ad-hoc locations with their
    // secrets are dropped.
    void revoke();
    // Cancels the work of the pools whose tokens were set (XB-13).
    void kick() const;
    void maintain(qint64 nowMs) const;

    QVector<LocationSpec> visible() const;
    bool find(const QString &id, LocationSpec *out) const;
    // The pool of a visible location (created on first use), or null with
    // NotFound; PermissionDenied without consent.
    Pool *pool(const QString &id, Result *error);
    Pool *existing(const QString &id) const;
    QString reserveAdHocId();
    QString addAdHoc(const LocationSpec &spec, std::unique_ptr<Pool> pool);
    bool forgetAdHoc(const QString &id);
    void disconnect(const QString &id) const;
    void closeWorkerHandle(const QString &loc, Worker *worker, quint32 handle) const;

    void setAttention(int accountId, Attention attention, const QString &seenPin) const;
    void fetch(int accountId, const AccountDirectory::Fetched &done) const;

    HostRegistry *hosts() { return &m_hosts; }
    Connector *connector() { return m_connector.get(); }

private:
    void wipeAdHocSecrets();

    BridgeServer *m_server;
    KnownHosts m_knownHosts;
    HostRegistry m_hosts;
    std::unique_ptr<BridgeConnector> m_connector;
    std::unique_ptr<AccountDirectory> m_accounts;
    QVector<AccountLocation> m_accountList;
    std::map<QString, LocationSpec> m_adHoc;
    quint64 m_nextAdHoc = 1;
    std::map<QString, std::unique_ptr<Pool>> m_pools;    // by location id; last: joins the workers first
};

// CopyAcross: two connections on a thread of their own, over the per-host
// limit TooManyConnections (XB-12).
class CopyJobs
{
public:
    using Body = std::function<Result(Backend *source, Backend *destination, QVariantMap *extra)>;
    // Runs on the main thread.
    using Done = std::function<void(const Result &result, const QVariantMap &extra)>;
    struct Job;

    explicit CopyJobs(BridgeServer *server) : m_server(server) {}
    ~CopyJobs();
    CopyJobs(const CopyJobs &) = delete;
    CopyJobs &operator=(const CopyJobs &) = delete;

    void start(const LocationSpec &source, const LocationSpec &destination, const TaskContext &task,
               const Body &body, const Done &done);
    // Cancels the connections of the jobs whose tokens were set (XB-13).
    void kick() const;
    bool idle() const { return m_jobs.empty(); }

private:
    BridgeServer *m_server;
    std::vector<std::shared_ptr<Job>> m_jobs;
};

// XD-5: discovery runs only while a consumer asked for it; the results go to
// the sessions that asked, at most every 250 ms.
class NearbyService
{
public:
    explicit NearbyService(BridgeServer *server);

    void setDiscovering(quint64 sessionId, bool on);
    // The session is gone.
    void forget(quint64 sessionId) { m_discovering.remove(sessionId); }

private:
    void schedule();
    void send() const;

    BridgeServer *m_server;
    std::unique_ptr<Discovery> m_discovery;
    QHash<quint64, bool> m_discovering;
    QTimer m_timer;
};

} // namespace NetVfs::Bridge

#endif
