// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_BRIDGESERVER_H
#define NETVFS_BRIDGE_BRIDGESERVER_H

#include "consentstore.h"
#include "consentprompt.h"
#include "location.h"

// The moc of Qt 5.6 (Sailfish SDK) cannot parse C++17 nested namespaces; it
// does not need the headers that have them.
#ifndef Q_MOC_RUN
#include "handoff.h"
#include "peercheck.h"
#include "questions.h"
#include "runtime.h"
#endif
#include "wireconnection.h"

#include <QtCore/QFileSystemWatcher>
#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QTimer>

#include <functional>
#include <memory>

namespace NetVfs {
class Discovery;
struct DiscoveredService;
}

namespace NetVfs {
namespace Bridge {

class CopyJobs;
class ConsumerQuota;
class LocationBook;
class NearbyService;
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
// consent (XB-6) and the sessions, and asks to be shut down 30 s after the
// last client left and no job runs. The locations in scope with their
// connection pools (XB-7, XB-12), the limits (XB-17), the copy jobs and the
// discovery are parts of its own (serverparts.h).
class BridgeServer : public QObject
{
    Q_OBJECT
public:
    explicit BridgeServer(const BridgeConfig &config, QObject *parent = nullptr);
    ~BridgeServer() override;

    Result start();
    QString address() const { return m_wire.address(); }

    // ---- used by sessions (main thread) ----
    const BridgeConfig &config() const { return m_config; }
    Consent consent() const { return m_consent; }
    void requestConsent();
    MainQueue *mainQueue() const { return m_queue.get(); }
    QuestionBroker *questions() { return &m_questions; }
    const Handoff &handoff() const { return m_handoff; }
    Session *session(quint64 id) const { return m_sessions.value(id); }
    QString tag() const;               // "[<consumer>]" for log lines

    ConsumerQuota *quota() const { return m_quota.get(); }
    LocationBook *locations() const { return m_locations.get(); }
    CopyJobs *copyJobs() const { return m_copyJobs.get(); }
    NearbyService *nearby() const { return m_nearby.get(); }

    // Cancels the running work whose tokens were set (XB-13).
    void kickAll() const;
    // The work in flight or the sessions changed: (re)starts or stops the idle timer.
    void updateIdleTimer();
    // Sends the signal `member` to every session that said Hello.
    void broadcast(const char *member, const std::function<void(WireWriter &writer)> &writer = nullptr) const;

Q_SIGNALS:
    // XB-2: 30 s without clients and jobs.
    void idleTimeout();

private:
    void onNewConnection(WireConnection *connection);
    void onSessionFinished(quint64 id);
    void reloadConsent();
    void applyConsent(Consent consent);
    void onPromptAnswered(bool allow);
    void watchConsentFile();

    BridgeConfig m_config;
    std::unique_ptr<MainQueue> m_queue = std::make_unique<MainQueue>();
    WireServer m_wire;
    ConsentStore m_consentStore;
    Consent m_consent = Consent::Unknown;
    QFileSystemWatcher m_watcher;
    std::unique_ptr<ConsentPrompt> m_prompt;
    QuestionBroker m_questions;
    Handoff m_handoff;
    std::unique_ptr<PeerChecker> m_peerChecker;
    std::unique_ptr<ConsumerQuota> m_quota;
    std::unique_ptr<LocationBook> m_locations;
    std::unique_ptr<CopyJobs> m_copyJobs;
    std::unique_ptr<NearbyService> m_nearby;

    QHash<quint64, Session *> m_sessions;
    quint64 m_nextSession = 1;
    QTimer m_idleTimer;
    QTimer m_maintenanceTimer;
};

} // namespace Bridge
} // namespace NetVfs

#endif
