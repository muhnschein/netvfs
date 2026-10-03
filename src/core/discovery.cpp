// SPDX-License-Identifier: LGPL-2.1-or-later
#include "discovery.h"

#include "discoverycache.h"
#include "discoverytransport.h"
#include "dnsmessage.h"
#include "logging.h"

#include <QtCore/QElapsedTimer>

#include <algorithm>
#include <climits>

namespace NetVfs {

namespace {

constexpr int MaxQueryBytes = 1400;               // stay well below the interface MTU
constexpr int QuestionsPerPacket = 20;
constexpr int MaxBackoffShift = 16;
constexpr int MaxBrowseCount = 31;
constexpr int MinTimerDelayMs = 1;

} // namespace

// ------------------------------------------------------------ DiscoveredService

QString DiscoveredService::key() const
{
    return (serviceType + QLatin1Char('/') + instanceName).toLower();
}

QString DiscoveredService::endpointKey() const
{
    return provider + QLatin1Char('|') + host.toLower() + QLatin1Char('|') + QString::number(port);
}

bool providerForServiceType(const QString &serviceType, QString *provider, QString *tls)
{
    const BrowseType *t = findBrowseType(serviceType);
    if (!t)
        return false;
    if (provider)
        *provider = QString::fromLatin1(t->provider);
    if (tls)
        *tls = QString::fromLatin1(t->tls);
    return true;
}

QStringList browsedServiceTypes()
{
    QStringList out;
    for (const BrowseType &t : browseTypeTable())
        out.append(QString::fromLatin1(t.type));
    return out;
}

ConnectionParams toConnectionParams(const DiscoveredService &service, QString *locationPath)
{
    ConnectionParams p;
    p.provider = service.provider;
    p.host = service.host;
    if (p.host.isEmpty() && !service.addresses.isEmpty())
        p.host = service.addresses.first().toString();
    p.port = service.port;
    p.username = service.user;
    QString location = QStringLiteral("/");
    if (service.provider == QLatin1String("webdav")) {
        p.options.insert(QStringLiteral("tls"), service.tls.isEmpty() ? QStringLiteral("https") : service.tls);
        p.options.insert(QStringLiteral("base_path"), service.path.isEmpty() ? QStringLiteral("/") : service.path);
    } else if (service.provider == QLatin1String("ftp") && !service.path.isEmpty()) {
        location = service.path;
    }
    if (locationPath)
        *locationPath = location;
    return p;
}

// ------------------------------------------------------------------ clock

DiscoveryClock::~DiscoveryClock() = default;

qint64 DiscoveryClock::monotonicMs() const
{
    static const QElapsedTimer base = []() {
        QElapsedTimer t;
        t.start();
        return t;
    }();
    return base.elapsed();
}

QDateTime DiscoveryClock::wallTime() const
{
    return QDateTime::currentDateTimeUtc();
}

// -------------------------------------------------------------- Discovery

class Discovery::Private
{
public:
    Private(Discovery *owner, DiscoveryTransport *t) : q(owner), transport(t), clock(&defaultClock)
    {
        timer.setSingleShot(true);
        QObject::connect(&timer, &QTimer::timeout, q, [this]() { runTimers(); });
        QObject::connect(transport, &DiscoveryTransport::datagramReceived, q,
                         [this](const QByteArray &data, const QHostAddress &sender) { onDatagram(data, sender); });
    }

    qint64 now() const { return clock->monotonicMs(); }

    void begin();
    void halt();
    void restartBackoff();
    void runTimers();
    void onDatagram(const QByteArray &data, const QHostAddress &sender);
    void sendBrowse(qint64 at) const;
    void sendQuestions(const QVector<Dns::Question> &questions) const;
    void flush(const ServiceCache::Events &events) const;
    void arm();

    Discovery *q;
    DiscoveryTransport *transport;
    ServiceCache cache;
    DiscoveryClock defaultClock;
    const DiscoveryClock *clock;
    QTimer timer;
    qint64 nextBrowseAt = 0;
    int browseCount = 0;
    quint64 generation = 0;      // bumped whenever the cache is dropped; aborts stale emissions
};

int Discovery::queryIntervalMs(int n)
{
    const int shift = std::max(0, std::min(n, MaxBackoffShift));
    const qint64 gap = static_cast<qint64>(FirstQueryIntervalMs) << shift;
    return static_cast<int>(std::min<qint64>(gap, MaxQueryIntervalMs));
}

Discovery::Discovery(QObject *parent)
    : Discovery(new MulticastTransport, parent)
{
}

Discovery::Discovery(DiscoveryTransport *transport, QObject *parent)
    : QObject(parent)
{
    qRegisterMetaType<DiscoveredService>("NetVfs::DiscoveredService");
    transport->setParent(this);
    d.reset(new Private(this, transport));
}

Discovery::~Discovery()
{
    if (m_consumers > 0)
        d->halt();
}

bool Discovery::start()
{
    ++m_consumers;
    if (m_consumers == 1)
        d->begin();
    return d->transport->isOpen();
}

void Discovery::stop()
{
    if (m_consumers <= 0)
        return;
    --m_consumers;
    if (m_consumers == 0)
        d->halt();
}

void Discovery::refresh()
{
    if (m_consumers > 0) {
        d->restartBackoff();
        d->runTimers();
    }
}

QVector<DiscoveredService> Discovery::services() const
{
    return d->cache.services();
}

void Discovery::setClock(const DiscoveryClock *clock)
{
    d->clock = clock ? clock : &d->defaultClock;
}

void Discovery::runTimers()
{
    d->runTimers();
}

void Discovery::Private::begin()
{
    qCDebug(lcNetVfsCore) << "discovery: started";
    ++generation;
    if (!transport->open())
        qCWarning(lcNetVfsCore) << "discovery: no mDNS socket could be opened, will retry";
    restartBackoff();
    runTimers();
}

void Discovery::Private::halt()
{
    qCDebug(lcNetVfsCore) << "discovery: stopped";
    ++generation;
    timer.stop();
    transport->close();
    cache.clear();
}

void Discovery::Private::restartBackoff()
{
    nextBrowseAt = now();
    browseCount = 0;
}

void Discovery::Private::runTimers()
{
    if (!q->isRunning())
        return;
    const qint64 t = now();
    if (t >= nextBrowseAt) {
        if (!transport->isOpen())
            transport->open();
        sendBrowse(t);
        nextBrowseAt = t + queryIntervalMs(browseCount);
        browseCount = std::min(browseCount + 1, MaxBrowseCount);
    }
    ServiceCache::Events events;
    cache.expire(t, &events);
    sendQuestions(cache.dueQuestions(t));
    flush(events);
    arm();
}

void Discovery::Private::onDatagram(const QByteArray &data, const QHostAddress &sender)
{
    Q_UNUSED(sender)
    if (!q->isRunning())
        return;
    Dns::Message message;
    if (QString why; !Dns::decode(data, &message, &why)) {
        qCDebug(lcNetVfsCore) << "discovery: dropped a malformed datagram:" << why;
        return;
    }
    ServiceCache::Events events;
    const qint64 t = now();
    cache.ingest(message, t, clock->wallTime(), &events);
    sendQuestions(cache.dueQuestions(t));
    flush(events);
    arm();
}

void Discovery::Private::sendBrowse(qint64 at) const
{
    Dns::Message message;
    for (const BrowseType &t : browseTypeTable()) {
        Dns::Question question;
        question.name = QByteArray(t.type) + ".local";
        question.type = Dns::TypePtr;
        message.questions.append(question);
    }
    // Known-answer suppression (RFC 6762 section 7.1): as many as fit.
    const QVector<Dns::Record> known = cache.knownAnswers(at);
    for (const Dns::Record &r : known) {
        message.answers.append(r);
        if (const int size = Dns::encode(message).size(); size == 0 || size > MaxQueryBytes) {
            message.answers.removeLast();
            break;
        }
    }
    transport->send(Dns::encode(message));
}

void Discovery::Private::sendQuestions(const QVector<Dns::Question> &questions) const
{
    for (int i = 0; i < questions.size(); i += QuestionsPerPacket) {
        Dns::Message message;
        message.questions = questions.mid(i, QuestionsPerPacket);
        if (const QByteArray packet = Dns::encode(message); !packet.isEmpty())
            transport->send(packet);
    }
}

void Discovery::Private::flush(const ServiceCache::Events &events) const
{
    const quint64 gen = generation;
    for (const ServiceCache::Event &e : events) {
        if (gen != generation || !q->isRunning())
            return;
        switch (e.kind) {
        case ServiceCache::EventKind::Found: emit q->found(e.service); break;
        case ServiceCache::EventKind::Updated: emit q->updated(e.service); break;
        case ServiceCache::EventKind::Lost: emit q->lost(e.service); break;
        }
    }
}

void Discovery::Private::arm()
{
    if (!q->isRunning()) {
        timer.stop();
        return;
    }
    qint64 next = nextBrowseAt;
    if (const qint64 deadline = cache.nextDeadline(); deadline >= 0 && deadline < next)
        next = deadline;
    const qint64 delay = std::max<qint64>(MinTimerDelayMs, next - now());
    timer.start(static_cast<int>(std::min<qint64>(delay, INT_MAX)));
}

} // namespace NetVfs
