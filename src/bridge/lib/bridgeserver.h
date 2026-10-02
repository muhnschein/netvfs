// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_BRIDGESERVER_H
#define NETVFS_BRIDGE_BRIDGESERVER_H

#include "consentstore.h"
#include "consentprompt.h"
#include "handoff.h"
#include "knownhosts.h"
#include "location.h"
#include "peercheck.h"
#include "pool.h"
#include "questions.h"
#include "runtime.h"
#include "wireconnection.h"

#include <QtCore/QFileSystemWatcher>
#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QTimer>

#include <functional>
#include <map>
#include <memory>

namespace NetVfs {
class Discovery;
struct DiscoveredService;
}

namespace NetVfs {
namespace Bridge {

class Session;

// XB-17: per-consumer limits.
namespace ConsumerLimits {
constexpr int Requests = 64;
constexpr int Handles = 16;
constexpr int Jobs = 8;
constexpr qint64 RetryAfterMs = 1000;
} // namespace ConsumerLimits

struct BridgeConfig {
    ConsumerInfo consumer;
    QString listenAddress = QStringLiteral("systemd:");
    QString consentFile = ConsentStore::defaultFilePath();
    QString knownHostsFile;                     // default: KnownHosts::defaultFilePath(consumer.id)
    QString handoffConfig = Handoff::defaultConfigPath();
    int idleExitMs = 30000;                     // XB-2
    qint64 connectionIdleMs = 60000;            // pooled connections without work
    int questionTimeoutMs = 10 * 60 * 1000;
    bool checkPeers = true;                     // XB-5; tests may inject the environment instead
    PeerChecker::Environment peerEnvironment;
    // Injected collaborators (owned by the server; defaults when null).
    AccountDirectory *accounts = nullptr;
    ConsentPrompt *prompt = nullptr;
    std::function<Discovery *()> discoveryFactory;
    Handoff::Launcher handoffLauncher;
};

// The bridge of one consumer (XB-2): listens, checks peers (XB-5), keeps the
// consent (XB-6), the locations in scope (XB-7) with their connection pools
// (XB-12), the questions and the per-consumer limits (XB-17), and asks to be
// shut down 30 s after the last client left and no job runs.
class BridgeServer : public QObject
{
    Q_OBJECT
public:
    explicit BridgeServer(const BridgeConfig &config, QObject *parent = nullptr);
    ~BridgeServer() override;

    Result start();
    QString address() const { return m_wire.address(); }

    // ---- used by sessions (main thread) ----
    const ConsumerInfo &consumer() const { return m_config.consumer; }
    const BridgeConfig &config() const { return m_config; }
    Consent consent() const { return m_consent; }
    void requestConsent();
    MainQueue *mainQueue() { return &m_queue; }
    QuestionBroker *questions() { return &m_questions; }
    const Handoff &handoff() const { return m_handoff; }
    HostRegistry *hosts() { return &m_hosts; }
    Connector *connector() { return m_connector.get(); }
    Session *session(quint64 id) const { return m_sessions.value(id); }
    QString tag() const;               // "[<consumer>]" for log lines

    QVector<LocationSpec> visibleLocations() const;
    bool findLocation(const QString &id, LocationSpec *out) const;
    // The pool of a visible location (created on first use), or null with
    // NotFound; PermissionDenied without consent.
    Pool *pool(const QString &id, Result *error);
    Pool *existingPool(const QString &id) const;
    QString reserveAdHocId();
    QString addAdHoc(const LocationSpec &spec, std::unique_ptr<Pool> pool);
    bool forgetAdHoc(const QString &id);
    void disconnectLocation(const QString &id);
    // Cancels the running work whose tokens were set (XB-13).
    void kickAll();
    void closeWorkerHandle(const QString &loc, Worker *worker, quint32 handle);

    // CopyAcross: two connections on a thread of their own; `done` runs on
    // the main thread. Over the per-host limit: TooManyConnections.
    using CopyBody = std::function<Result(Backend *source, Backend *destination, QVariantMap *extra)>;
    using CopyDone = std::function<void(const Result &result, const QVariantMap &extra)>;
    void startCopyJob(const LocationSpec &source, const LocationSpec &destination, const TaskContext &task,
                      const CopyBody &body, const CopyDone &done);
    void setAttention(int accountId, Attention attention, const QString &seenPin);
    void fetchAccount(int accountId, const AccountDirectory::Fetched &done);
    QString pinFor(const LocationSpec &spec) const;
    bool storePin(const LocationSpec &spec, const QString &pin);

    bool acquireRequest();
    void releaseRequest();
    bool acquireHandle();
    void releaseHandle();
    bool acquireJob();
    void releaseJob();
    int activeRequests() const { return m_requests; }
    int openHandles() const { return m_handles; }
    int runningJobs() const { return m_jobs; }

    void setDiscovering(quint64 sessionId, bool on);
    void noteActivity();

Q_SIGNALS:
    // XB-2: 30 s without clients and jobs.
    void idleTimeout();
    void consentChanged(NetVfs::Consent consent);

private:
    void onNewConnection(WireConnection *connection);
    void onSessionFinished(quint64 id);
    void reloadConsent();
    void applyConsent(Consent consent);
    void onPromptAnswered(bool allow);
    void refreshAccounts();
    void broadcast(const char *member);
    void maintainPools();
    void updateIdleTimer();
    void scheduleNearby();
    void sendNearby();
    void closeAllSessions();
    void watchConsentFile();

    BridgeConfig m_config;
    MainQueue m_queue;
    WireServer m_wire;
    ConsentStore m_consentStore;
    Consent m_consent = Consent::Unknown;
    QFileSystemWatcher m_watcher;
    std::unique_ptr<ConsentPrompt> m_prompt;
    std::unique_ptr<AccountDirectory> m_accounts;
    QVector<AccountLocation> m_accountList;
    KnownHosts m_knownHosts;
    QuestionBroker m_questions;
    Handoff m_handoff;
    HostRegistry m_hosts;
    std::unique_ptr<Connector> m_connector;
    std::unique_ptr<PeerChecker> m_peerChecker;

    std::map<QString, std::unique_ptr<Pool>> m_pools;    // by location id
    std::map<QString, LocationSpec> m_adHoc;
    quint64 m_nextAdHoc = 1;

    QHash<quint64, Session *> m_sessions;
    quint64 m_nextSession = 1;
    int m_requests = 0;
    int m_handles = 0;
    int m_jobs = 0;

    struct CopyJob;
    std::vector<std::shared_ptr<CopyJob>> m_copyJobs;

    std::unique_ptr<Discovery> m_discovery;
    QHash<quint64, bool> m_discovering;
    QTimer m_nearbyTimer;

    QTimer m_idleTimer;
    QTimer m_maintenanceTimer;
};

} // namespace Bridge
} // namespace NetVfs

#endif
