// SPDX-License-Identifier: LGPL-2.1-or-later
#include "serverparts.h"

#include "backendloader.h"
#include "names.h"
#include "session.h"

#include <algorithm>

namespace NetVfs::Bridge {

// ----------------------------------------------------------- ConsumerQuota

bool ConsumerQuota::acquireRequest()
{
    if (m_requests >= ConsumerLimits::Requests)
        return false;
    ++m_requests;
    m_server->updateIdleTimer();
    return true;
}

void ConsumerQuota::releaseRequest()
{
    m_requests = std::max(0, m_requests - 1);
    m_server->updateIdleTimer();
}

bool ConsumerQuota::acquireHandle()
{
    if (m_handles >= ConsumerLimits::Handles)
        return false;
    ++m_handles;
    return true;
}

void ConsumerQuota::releaseHandle()
{
    m_handles = std::max(0, m_handles - 1);
}

bool ConsumerQuota::acquireJob()
{
    if (m_jobs >= ConsumerLimits::Jobs)
        return false;
    ++m_jobs;
    m_server->updateIdleTimer();
    return true;
}

void ConsumerQuota::releaseJob()
{
    m_jobs = std::max(0, m_jobs - 1);
    m_server->updateIdleTimer();
}

// -------------------------------------------------------------- CopyJobs

struct CopyJobs::Job {
    CancelTokenPtr token;
    std::mutex mutex;
    std::vector<Backend *> backends;     // while connected; canceled by kick()
    std::thread thread;
};

namespace {

Result tooManyConnections()
{
    return Result(Error::TooManyConnections, QStringLiteral("Too many connections to the server"), QString(),
                  ConsumerLimits::RetryAfterMs);
}

// The thread of one copy job: both connections, the copy, the disconnects.
template <typename Body>
Result runCopy(CopyJobs::Job *job, Connector *connector, const LocationSpec &source,
               const LocationSpec &destination, const TaskContext &task, const Body &body, QVariantMap *extra)
{
    std::unique_ptr<Backend> src(BackendLoader::create(source.provider));
    std::unique_ptr<Backend> dst(BackendLoader::create(destination.provider));
    Result r;
    if (!src || !dst) {
        r = Result(Error::Unsupported, QStringLiteral("No backend for this location"));
    } else {
        {
            std::scoped_lock lock(job->mutex);
            job->backends = { src.get(), dst.get() };
        }
        r = connector->establish(src.get(), source, task);
        if (r.ok())
            r = connector->establish(dst.get(), destination, task);
        if (r.ok())
            r = body(src.get(), dst.get(), extra);
        std::scoped_lock lock(job->mutex);
        job->backends.clear();
    }
    if (src)
        src->disconnect();
    if (dst)
        dst->disconnect();
    return r;
}

} // namespace

CopyJobs::~CopyJobs()
{
    for (const auto &job : m_jobs) {
        job->token->cancel();
        {
            std::scoped_lock lock(job->mutex);
            for (Backend *b : job->backends)
                b->cancel();
        }
        if (job->thread.joinable())
            job->thread.join();
    }
}

void CopyJobs::start(const LocationSpec &source, const LocationSpec &destination, const TaskContext &task,
                     const Body &body, const Done &done)
{
    HostRegistry *hosts = m_server->locations()->hosts();
    const QString sourceHost = source.hostKey();
    const QString destinationHost = destination.hostKey();
    if (!hosts->tryAcquire(sourceHost)) {
        done(tooManyConnections(), QVariantMap());
        return;
    }
    if (!hosts->tryAcquire(destinationHost)) {
        hosts->release(sourceHost);
        done(tooManyConnections(), QVariantMap());
        return;
    }
    auto job = std::make_shared<Job>();
    job->token = task.token;
    m_jobs.push_back(job);
    Connector *connector = m_server->locations()->connector();
    MainQueue *queue = m_server->mainQueue();
    job->thread = std::thread([this, queue, job, connector, source, destination, task, body, done, sourceHost,
                               destinationHost]() {
        QVariantMap extra;
        const Result r = runCopy(job.get(), connector, source, destination, task, body, &extra);
        queue->post([this, job, r, extra, done, sourceHost, destinationHost]() {
            if (job->thread.joinable())
                job->thread.join();
            m_jobs.erase(std::remove(m_jobs.begin(), m_jobs.end(), job), m_jobs.end());
            HostRegistry *registry = m_server->locations()->hosts();
            registry->release(sourceHost);
            registry->release(destinationHost);
            registry->notifyReleased(sourceHost);
            registry->notifyReleased(destinationHost);
            done(r, extra);
            m_server->updateIdleTimer();
        });
    });
}

void CopyJobs::kick() const
{
    for (const auto &job : m_jobs) {
        if (!job->token->isCanceled())
            continue;
        std::scoped_lock lock(job->mutex);
        for (Backend *b : job->backends)
            b->cancel();
    }
}

// ---------------------------------------------------------- NearbyService

namespace {

constexpr int NearbyDelayMs = 250;

// The injected factory's discovery belongs to the service.
std::unique_ptr<Discovery> discoveryFor(const std::function<Discovery *()> &factory)
{
    if (factory)
        return std::unique_ptr<Discovery>(factory());
    return std::make_unique<Discovery>();
}

void writeServices(WireWriter &w, const QVector<DiscoveredService> &services)
{
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
}

} // namespace

NearbyService::NearbyService(BridgeServer *server)
    : m_server(server)
{
    m_timer.setSingleShot(true);
    m_timer.setInterval(NearbyDelayMs);
    QObject::connect(&m_timer, &QTimer::timeout, &m_timer, [this]() { send(); });
}

void NearbyService::setDiscovering(quint64 sessionId, bool on)
{
    if (on == m_discovering.contains(sessionId))
        return;
    if (!on) {
        m_discovering.remove(sessionId);
        if (m_discovery)
            m_discovery->stop();
        return;
    }
    if (!m_discovery) {
        m_discovery = discoveryFor(m_server->config().discoveryFactory);
        QObject::connect(m_discovery.get(), &Discovery::found, &m_timer, [this]() { schedule(); });
        QObject::connect(m_discovery.get(), &Discovery::updated, &m_timer, [this]() { schedule(); });
        QObject::connect(m_discovery.get(), &Discovery::lost, &m_timer, [this]() { schedule(); });
    }
    m_discovering.insert(sessionId, true);
    m_discovery->start();
    schedule();
}

void NearbyService::schedule()
{
    if (!m_timer.isActive())
        m_timer.start();
}

void NearbyService::send() const
{
    if (!m_discovery || m_server->consent() != Consent::Granted)
        return;
    const QVector<DiscoveredService> services = m_discovery->services();
    const Session::Writer writer = [services](WireWriter &w) { writeServices(w, services); };
    for (auto it = m_discovering.cbegin(); it != m_discovering.cend(); ++it) {
        if (Session *s = m_server->session(it.key()))
            s->sendSignal("NearbyChanged", writer);
    }
}

} // namespace NetVfs::Bridge
