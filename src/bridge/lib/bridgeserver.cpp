// SPDX-License-Identifier: LGPL-2.1-or-later
#include "bridgeserver.h"

#include "backendloader.h"
#include "bridgelog.h"
#include "connector.h"
#include "discovery.h"
#include "names.h"
#include "protocol.h"
#include "session.h"

#include <QtCore/QDir>
#include <QtCore/QFileInfo>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <mutex>
#include <thread>

Q_LOGGING_CATEGORY(lcNetVfsBridge, "netvfs.bridge", QtWarningMsg)

namespace NetVfs {
namespace Bridge {

namespace {

constexpr int MaintenanceIntervalMs = 5000;
constexpr int NearbyDelayMs = 250;

qint64 steadyMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

QString accountLocationId(int accountId)
{
    return QStringLiteral("account:") + QString::number(accountId);
}

LocationSpec specFor(const AccountLocation &account)
{
    LocationSpec spec;
    spec.id = accountLocationId(account.accountId);
    spec.kind = LocationKind::Account;
    spec.accountId = account.accountId;
    spec.provider = account.provider;
    spec.name = account.displayName;
    spec.params = account.params;
    spec.startPath = account.filesRoot;
    spec.attention = account.attention;
    return spec;
}

bool sameConnection(const ConnectionParams &a, const ConnectionParams &b)
{
    return a.provider == b.provider && a.host == b.host && a.port == b.port && a.username == b.username
        && a.options == b.options;
}

} // namespace

struct BridgeServer::CopyJob {
    CancelTokenPtr token;
    std::mutex mutex;
    std::vector<Backend *> backends;     // while connected; canceled by kickAll()
    std::thread thread;
};

BridgeServer::BridgeServer(const BridgeConfig &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
    , m_consentStore(config.consentFile)
    , m_prompt(config.prompt ? config.prompt : new NotificationConsentPrompt)
    , m_accounts(config.accounts ? config.accounts : new LibAccountsDirectory)
    , m_knownHosts(config.knownHostsFile.isEmpty() ? KnownHosts::defaultFilePath(config.consumer.id)
                                                   : config.knownHostsFile)
    , m_handoff(config.handoffConfig)
{
    // A FIFO whose reader went away must fail the job, not kill the process.
    std::signal(SIGPIPE, SIG_IGN);
    if (m_config.handoffLauncher)
        m_handoff.setLauncher(m_config.handoffLauncher);
    m_connector = std::make_unique<BridgeConnector>(this, &m_knownHosts, m_config.questionTimeoutMs);
    m_peerChecker = std::make_unique<PeerChecker>(m_config.consumer.executable, m_config.peerEnvironment);

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
    connect(m_accounts.get(), &AccountDirectory::changed, this, &BridgeServer::refreshAccounts);
    connect(&m_watcher, &QFileSystemWatcher::fileChanged, this, &BridgeServer::reloadConsent);
    connect(&m_watcher, &QFileSystemWatcher::directoryChanged, this, &BridgeServer::reloadConsent);

    m_idleTimer.setSingleShot(true);
    connect(&m_idleTimer, &QTimer::timeout, this, [this]() {
        if (m_sessions.isEmpty() && m_jobs == 0 && m_requests == 0 && m_copyJobs.empty())
            emit idleTimeout();
    });
    m_maintenanceTimer.setInterval(MaintenanceIntervalMs);
    connect(&m_maintenanceTimer, &QTimer::timeout, this, &BridgeServer::maintainPools);
    m_nearbyTimer.setSingleShot(true);
    m_nearbyTimer.setInterval(NearbyDelayMs);
    connect(&m_nearbyTimer, &QTimer::timeout, this, &BridgeServer::sendNearby);
}

BridgeServer::~BridgeServer()
{
    m_wire.stop();
    const QList<Session *> sessions = m_sessions.values();
    m_sessions.clear();
    for (Session *s : sessions) {
        s->cancelAll();
        delete s;
    }
    for (const auto &job : m_copyJobs) {
        job->token->cancel();
        {
            std::lock_guard<std::mutex> lock(job->mutex);
            for (Backend *b : job->backends)
                b->cancel();
        }
        if (job->thread.joinable())
            job->thread.join();
    }
    m_copyJobs.clear();
    m_pools.clear();     // joins the workers
    for (auto &entry : m_adHoc) {
        if (entry.second.adHocCredentials)
            entry.second.adHocCredentials->wipe();
    }
    m_discovery.reset();
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
    m_accountList = m_accounts->filesAccounts();
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
    Session *s = m_sessions.take(id);
    if (s)
        s->deleteLater();
    m_discovering.remove(id);
    qCDebug(lcNetVfsBridge).noquote() << tag() << "Client" << id << "disconnected";
    updateIdleTimer();
}

void BridgeServer::closeAllSessions()
{
    const QList<Session *> sessions = m_sessions.values();
    for (Session *s : sessions)
        s->closeConnection();
}

void BridgeServer::broadcast(const char *member)
{
    const QList<Session *> sessions = m_sessions.values();
    for (Session *s : sessions) {
        if (s->helloDone())
            s->sendSignal(member, Session::Writer());
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
    const QList<Session *> sessions = m_sessions.values();
    for (Session *s : sessions) {
        if (s->helloDone())
            s->sendSignal("ConsentChanged", [value](WireWriter &w) { w.string(value); });
    }
    if (previous == Consent::Granted) {
        // XB-6: revocation closes the consumer's connections at once and
        // cancels its work; ad-hoc locations and their secrets are dropped.
        qCWarning(lcNetVfsBridge).noquote() << tag() << "Consent revoked; closing all connections";
        closeAllSessions();
        m_pools.clear();
        for (auto &entry : m_adHoc) {
            if (entry.second.adHocCredentials)
                entry.second.adHocCredentials->wipe();
        }
        m_adHoc.clear();
    } else if (consent == Consent::Granted) {
        broadcast("LocationsChanged");
    }
    emit consentChanged(consent);
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

// -------------------------------------------------------------- locations

void BridgeServer::refreshAccounts()
{
    const QVector<AccountLocation> accounts = m_accounts->filesAccounts();
    QHash<QString, AccountLocation> byId;
    for (const AccountLocation &a : accounts)
        byId.insert(accountLocationId(a.accountId), a);
    for (auto it = m_pools.begin(); it != m_pools.end();) {
        const LocationSpec &spec = it->second->spec();
        const bool account = spec.kind == LocationKind::Account;
        const auto found = byId.constFind(spec.id);
        if (account && (found == byId.constEnd() || !sameConnection(found->params, spec.params)))
            it = m_pools.erase(it);   // removed or changed: new connections use the new settings
        else
            ++it;
    }
    m_accountList = accounts;
    if (m_consent == Consent::Granted)
        broadcast("LocationsChanged");
}

QVector<LocationSpec> BridgeServer::visibleLocations() const
{
    QVector<LocationSpec> result;
    for (const AccountLocation &a : m_accountList)
        result << specFor(a);
    for (const auto &entry : m_adHoc)
        result << entry.second;
    return result;
}

bool BridgeServer::findLocation(const QString &id, LocationSpec *out) const
{
    for (const AccountLocation &a : m_accountList) {
        if (accountLocationId(a.accountId) == id) {
            *out = specFor(a);
            return true;
        }
    }
    const auto it = m_adHoc.find(id);
    if (it == m_adHoc.end())
        return false;
    *out = it->second;
    return true;
}

Pool *BridgeServer::existingPool(const QString &id) const
{
    const auto it = m_pools.find(id);
    return it == m_pools.end() ? nullptr : it->second.get();
}

Pool *BridgeServer::pool(const QString &id, Result *error)
{
    if (m_consent != Consent::Granted) {
        *error = Result(Error::PermissionDenied, QStringLiteral("The user has not allowed this app to use network locations"));
        return nullptr;
    }
    if (Pool *existing = existingPool(id))
        return existing;
    LocationSpec spec;
    if (!findLocation(id, &spec)) {
        *error = Result(Error::NotFound, QStringLiteral("No such location"));
        return nullptr;
    }
    if (!BackendLoader::isAvailable(spec.provider)) {
        // XP-5: a missing backend package is Unsupported.
        *error = Result(Error::Unsupported, QStringLiteral("No backend for %1 is installed").arg(spec.provider));
        return nullptr;
    }
    auto created = std::make_unique<Pool>(spec, m_connector.get(), &m_hosts);
    Pool *raw = created.get();
    m_pools[id] = std::move(created);
    return raw;
}

QString BridgeServer::reserveAdHocId()
{
    return QStringLiteral("adhoc:") + QString::number(m_nextAdHoc++);
}

QString BridgeServer::addAdHoc(const LocationSpec &spec, std::unique_ptr<Pool> pool)
{
    m_adHoc[spec.id] = spec;
    m_pools[spec.id] = std::move(pool);
    broadcast("LocationsChanged");
    return spec.id;
}

bool BridgeServer::forgetAdHoc(const QString &id)
{
    const auto it = m_adHoc.find(id);
    if (it == m_adHoc.end())
        return false;
    // XB-14: forgetting drops the pin, so the next contact asks again.
    m_knownHosts.remove(it->second.hostKey());
    if (it->second.adHocCredentials)
        it->second.adHocCredentials->wipe();
    m_adHoc.erase(it);
    m_pools.erase(id);
    broadcast("LocationsChanged");
    return true;
}

void BridgeServer::disconnectLocation(const QString &id)
{
    if (Pool *p = existingPool(id))
        p->stopAll();
}

void BridgeServer::kickAll()
{
    for (auto &entry : m_pools)
        entry.second->kick();
    for (const auto &job : m_copyJobs) {
        if (!job->token->isCanceled())
            continue;
        std::lock_guard<std::mutex> lock(job->mutex);
        for (Backend *b : job->backends)
            b->cancel();
    }
}

void BridgeServer::closeWorkerHandle(const QString &loc, Worker *worker, quint32 handle)
{
    Pool *p = existingPool(loc);
    if (!p || !worker || !p->owns(worker))
        return;   // the connection is gone and its handles with it
    Pool::submitTo(worker, TaskContext(), [handle](Backend *, const Result &, Worker *w) {
        if (w)
            w->closeHandle(handle);
        return Result::success();
    });
}

void BridgeServer::setAttention(int accountId, Attention attention, const QString &seenPin)
{
    m_accounts->setAttention(accountId, attention, seenPin);
}

void BridgeServer::fetchAccount(int accountId, const AccountDirectory::Fetched &done)
{
    m_accounts->fetch(accountId, done);
}

QString BridgeServer::pinFor(const LocationSpec &spec) const
{
    return m_knownHosts.pin(spec.hostKey());
}

bool BridgeServer::storePin(const LocationSpec &spec, const QString &pin)
{
    return m_knownHosts.setPin(spec.hostKey(), pin);
}

void BridgeServer::maintainPools()
{
    const qint64 now = steadyMs();
    for (auto &entry : m_pools)
        entry.second->maintain(now, m_config.connectionIdleMs);
}

// ----------------------------------------------------------- copy jobs

void BridgeServer::startCopyJob(const LocationSpec &source, const LocationSpec &destination, const TaskContext &task,
                                const CopyBody &body, const CopyDone &done)
{
    const QString sourceHost = source.hostKey();
    const QString destinationHost = destination.hostKey();
    if (!m_hosts.tryAcquire(sourceHost)) {
        done(Result(Error::TooManyConnections, QStringLiteral("Too many connections to the server"), QString(),
                    ConsumerLimits::RetryAfterMs), QVariantMap());
        return;
    }
    if (!m_hosts.tryAcquire(destinationHost)) {
        m_hosts.release(sourceHost);
        done(Result(Error::TooManyConnections, QStringLiteral("Too many connections to the server"), QString(),
                    ConsumerLimits::RetryAfterMs), QVariantMap());
        return;
    }
    auto job = std::make_shared<CopyJob>();
    job->token = task.token;
    m_copyJobs.push_back(job);
    Connector *connector = m_connector.get();
    MainQueue *queue = &m_queue;
    job->thread = std::thread([this, job, connector, queue, source, destination, task, body, done, sourceHost,
                               destinationHost]() {
        std::unique_ptr<Backend> src(BackendLoader::create(source.provider));
        std::unique_ptr<Backend> dst(BackendLoader::create(destination.provider));
        Result r;
        QVariantMap extra;
        if (!src || !dst) {
            r = Result(Error::Unsupported, QStringLiteral("No backend for this location"));
        } else {
            {
                std::lock_guard<std::mutex> lock(job->mutex);
                job->backends = { src.get(), dst.get() };
            }
            r = connector->establish(src.get(), source, task);
            if (r.ok())
                r = connector->establish(dst.get(), destination, task);
            if (r.ok())
                r = body(src.get(), dst.get(), &extra);
            std::lock_guard<std::mutex> lock(job->mutex);
            job->backends.clear();
        }
        if (src)
            src->disconnect();
        if (dst)
            dst->disconnect();
        queue->post([this, job, r, extra, done, sourceHost, destinationHost]() {
            if (job->thread.joinable())
                job->thread.join();
            m_copyJobs.erase(std::remove(m_copyJobs.begin(), m_copyJobs.end(), job), m_copyJobs.end());
            m_hosts.release(sourceHost);
            m_hosts.release(destinationHost);
            m_hosts.notifyReleased(sourceHost);
            m_hosts.notifyReleased(destinationHost);
            done(r, extra);
            updateIdleTimer();
        });
    });
}

// ------------------------------------------------------------------ limits

bool BridgeServer::acquireRequest()
{
    if (m_requests >= ConsumerLimits::Requests)
        return false;
    ++m_requests;
    m_idleTimer.stop();
    return true;
}

void BridgeServer::releaseRequest()
{
    m_requests = std::max(0, m_requests - 1);
    updateIdleTimer();
}

bool BridgeServer::acquireHandle()
{
    if (m_handles >= ConsumerLimits::Handles)
        return false;
    ++m_handles;
    return true;
}

void BridgeServer::releaseHandle()
{
    m_handles = std::max(0, m_handles - 1);
}

bool BridgeServer::acquireJob()
{
    if (m_jobs >= ConsumerLimits::Jobs)
        return false;
    ++m_jobs;
    m_idleTimer.stop();
    return true;
}

void BridgeServer::releaseJob()
{
    m_jobs = std::max(0, m_jobs - 1);
    updateIdleTimer();
}

void BridgeServer::noteActivity()
{
    updateIdleTimer();
}

void BridgeServer::updateIdleTimer()
{
    const bool idle = m_sessions.isEmpty() && m_jobs == 0 && m_requests == 0 && m_copyJobs.empty()
        && !m_prompt->isShown();
    if (!idle)
        m_idleTimer.stop();
    else if (!m_idleTimer.isActive())
        m_idleTimer.start(m_config.idleExitMs);
}

// --------------------------------------------------------------- discovery

void BridgeServer::setDiscovering(quint64 sessionId, bool on)
{
    // XD-5: discovery runs only while a consumer asked for it.
    if (on == m_discovering.contains(sessionId))
        return;
    if (on) {
        if (!m_discovery) {
            m_discovery.reset(m_config.discoveryFactory ? m_config.discoveryFactory() : new Discovery);
            connect(m_discovery.get(), &Discovery::found, this, &BridgeServer::scheduleNearby);
            connect(m_discovery.get(), &Discovery::updated, this, &BridgeServer::scheduleNearby);
            connect(m_discovery.get(), &Discovery::lost, this, &BridgeServer::scheduleNearby);
        }
        m_discovering.insert(sessionId, true);
        m_discovery->start();
        scheduleNearby();
    } else {
        m_discovering.remove(sessionId);
        if (m_discovery)
            m_discovery->stop();
    }
}

void BridgeServer::scheduleNearby()
{
    if (!m_nearbyTimer.isActive())
        m_nearbyTimer.start();
}

void BridgeServer::sendNearby()
{
    if (!m_discovery || m_consent != Consent::Granted)
        return;
    const QVector<DiscoveredService> services = m_discovery->services();
    const Session::Writer writer = [services](WireWriter &w) {
        w.openArray("(sssqay)");
        for (const DiscoveredService &s : services) {
            w.openStruct()
                .string(s.instanceName)
                .string(s.provider)
                .string(s.host)
                .uint16(static_cast<quint16>(s.port))
                .bytes(Names::encode(s.path))
                .close();
        }
        w.close();
    };
    for (auto it = m_discovering.cbegin(); it != m_discovering.cend(); ++it) {
        if (Session *s = session(it.key()))
            s->sendSignal("NearbyChanged", writer);
    }
}

} // namespace Bridge
} // namespace NetVfs
