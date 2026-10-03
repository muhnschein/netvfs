// SPDX-License-Identifier: LGPL-2.1-or-later
#include "bridgeserver.h"

#include "bridgelog.h"
#include "protocol.h"
#include "serverparts.h"
#include "session.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>

#include <chrono>
#include <csignal>
#include <utility>

Q_LOGGING_CATEGORY(lcNetVfsBridge, "netvfs.bridge", QtWarningMsg)

namespace NetVfs::Bridge {

namespace {

constexpr int MaintenanceIntervalMs = 5000;

qint64 steadyMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// The injected prompt belongs to the server; without one the notification
// prompt is used.
std::unique_ptr<ConsentPrompt> promptFor(ConsentPrompt *injected)
{
    if (injected)
        return std::unique_ptr<ConsentPrompt>(injected);
    return std::make_unique<NotificationConsentPrompt>();
}

} // namespace

BridgeServer::BridgeServer(const BridgeConfig &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
    , m_consentStore(config.consentFile)
    , m_prompt(promptFor(config.prompt))
    , m_handoff(config.handoffConfig)
{
    // A FIFO whose reader went away must fail the job, not kill the process.
    std::signal(SIGPIPE, SIG_IGN);
    if (m_config.handoffLauncher)
        m_handoff.setLauncher(m_config.handoffLauncher);
    m_peerChecker = std::make_unique<PeerChecker>(m_config.consumer.executable, m_config.peerEnvironment);
    m_quota = std::make_unique<ConsumerQuota>(this);
    m_locations = std::make_unique<LocationBook>(this, config.accounts);
    m_copyJobs = std::make_unique<CopyJobs>(this);
    m_nearby = std::make_unique<NearbyService>(this);

    m_questions.setEmitter([this](quint64 sessionId, const QString &id, const QString &kind,
                                  const QVariantMap &details) {
        Session *s = session(sessionId);
        if (!s)
            return false;
        s->sendSignal("Question", [id, kind, details](WireWriter &w) { w.string(id).string(kind).variantMap(details); });
        return true;
    });

    connect(&m_wire, &WireServer::newConnection, this, &BridgeServer::onNewConnection);
    connect(m_prompt.get(), &ConsentPrompt::answered, this, &BridgeServer::onPromptAnswered);
    connect(m_prompt.get(), &ConsentPrompt::dismissed, this, &BridgeServer::updateIdleTimer);
    connect(&m_watcher, &QFileSystemWatcher::fileChanged, this, &BridgeServer::reloadConsent);
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, &BridgeServer::reloadConsent);

    m_idleTimer.setSingleShot(true);
    connect(&m_idleTimer, &QTimer::timeout, this, [this]() {
        if (m_sessions.isEmpty() && m_quota->runningJobs() == 0 && m_quota->activeRequests() == 0
                && m_copyJobs->idle())
            emit idleTimeout();
    });
    m_maintenanceTimer.setInterval(MaintenanceIntervalMs);
    connect(&m_maintenanceTimer, &QTimer::timeout, this, [this]() { m_locations->maintain(steadyMs()); });
}

BridgeServer::~BridgeServer()
{
    m_wire.stop();
    // The sessions go first: they cancel their work through the parts.
    const QHash<quint64, Session *> sessions = std::exchange(m_sessions, QHash<quint64, Session *>());
    for (Session *s : sessions)
        s->cancelAll();
    qDeleteAll(sessions);
}

QString BridgeServer::tag() const
{
    return consumerTag(m_config.consumer.id);
}

Result BridgeServer::start()
{
    if (const Result r = m_wire.listen(m_config.listenAddress); !r.ok())
        return r;
    watchConsentFile();
    m_consent = m_consentStore.consent(m_config.consumer.id);
    m_locations->load();
    m_maintenanceTimer.start();
    updateIdleTimer();
    qCDebug(lcNetVfsBridge).noquote() << tag() << "Listening on" << m_wire.address();
    return Result::success();
}

// ------------------------------------------------------------ connections

void BridgeServer::onNewConnection(WireConnection *connection)
{
    if (m_config.checkPeers) {
        // XB-5: closed without a reply, logged at warning level.
        if (const Result r = m_peerChecker->check(connection->socketFd()); !r.ok()) {
            qCWarning(lcNetVfsBridge).noquote() << tag() << "Refused a connection:" << r.message();
            connection->close();
            connection->deleteLater();
            return;
        }
    }
    const quint64 id = m_nextSession++;
    auto *s = new Session(id, connection, this);
    m_sessions.insert(id, s);
    connect(s, &Session::finished, this, &BridgeServer::onSessionFinished);
    qCDebug(lcNetVfsBridge).noquote() << tag() << "Client" << id << "connected";
    updateIdleTimer();
}

void BridgeServer::onSessionFinished(quint64 id)
{
    if (Session *s = m_sessions.take(id))
        s->deleteLater();
    m_nearby->forget(id);
    qCDebug(lcNetVfsBridge).noquote() << tag() << "Client" << id << "disconnected";
    updateIdleTimer();
}

void BridgeServer::broadcast(const char *member, const std::function<void(WireWriter &)> &writer) const
{
    const QList<Session *> sessions = m_sessions.values();
    for (Session *s : sessions) {
        if (s->helloDone())
            s->sendSignal(member, writer);
    }
}

// ---------------------------------------------------------------- consent

void BridgeServer::watchConsentFile()
{
    const QFileInfo info(m_consentStore.filePath());
    QDir().mkpath(info.absolutePath());
    if (!m_watcher.directories().contains(info.absolutePath()))
        m_watcher.addPath(info.absolutePath());
    if (info.exists() && !m_watcher.files().contains(info.absoluteFilePath()))
        m_watcher.addPath(info.absoluteFilePath());
}

void BridgeServer::reloadConsent()
{
    watchConsentFile();   // writers replace the file; watch the new one
    applyConsent(m_consentStore.consent(m_config.consumer.id));
}

void BridgeServer::applyConsent(Consent consent)
{
    if (consent == m_consent)
        return;
    const Consent previous = m_consent;
    m_consent = consent;
    qCDebug(lcNetVfsBridge).noquote() << tag() << "Consent" << consentToString(consent);
    if (consent != Consent::Unknown)
        m_prompt->withdraw();
    const QString value = consentToString(consent);
    broadcast("ConsentChanged", [value](WireWriter &w) { w.string(value); });
    if (previous == Consent::Granted) {
        // XB-6: revocation closes the consumer's connections at once and
        // cancels its work; ad-hoc locations and their secrets are dropped.
        qCWarning(lcNetVfsBridge).noquote() << tag() << "Consent revoked; closing all connections";
        const QList<Session *> sessions = m_sessions.values();
        for (Session *s : sessions)
            s->closeConnection();
        m_locations->revoke();
    } else if (consent == Consent::Granted) {
        broadcast("LocationsChanged");
    }
    updateIdleTimer();
}

void BridgeServer::requestConsent()
{
    if (m_consent == Consent::Granted || m_prompt->isShown())
        return;
    m_prompt->show(m_config.consumer.displayName);
    updateIdleTimer();
}

void BridgeServer::onPromptAnswered(bool allow)
{
    const Consent consent = allow ? Consent::Granted : Consent::Denied;
    m_consentStore.setConsent(m_config.consumer.id, consent);
    applyConsent(consent);
}

// ------------------------------------------------------------------ work

void BridgeServer::kickAll() const
{
    m_locations->kick();
    m_copyJobs->kick();
}

void BridgeServer::updateIdleTimer()
{
    const bool idle = m_sessions.isEmpty() && m_quota->runningJobs() == 0 && m_quota->activeRequests() == 0
        && m_copyJobs->idle() && !m_prompt->isShown();
    if (!idle)
        m_idleTimer.stop();
    else if (!m_idleTimer.isActive())
        m_idleTimer.start(m_config.idleExitMs);
}

} // namespace NetVfs::Bridge
