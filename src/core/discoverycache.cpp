// SPDX-License-Identifier: LGPL-2.1-or-later
#include "discoverycache.h"

#include <algorithm>
#include <utility>

namespace NetVfs {

namespace {

constexpr int MsPerSecond = 1000;
constexpr int PercentDivisor = 100;
constexpr std::array<int, ServiceCache::RefreshStages> RefreshPercent = {{80, 90, 95}};
constexpr int MaxTextLength = 256;
constexpr int MaxPathLength = 1024;
constexpr int MaxHostLength = 253;
constexpr int CacheFlushGraceMs = 1000;          // RFC 6762 section 10.2
constexpr int GoodbyeGraceMs = 1000;             // RFC 6762 section 10.1 (TXT only, see handleTxt)
constexpr int ControlLimit = 0x20;
constexpr int C1First = 0x7F;
constexpr int C1Last = 0x9F;
constexpr int Ipv6LinkLocalPrefix = 10;
constexpr int Ipv4MulticastPrefix = 4;
constexpr int Ipv4LoopbackPrefix = 8;
constexpr int Ipv6MulticastPrefix = 8;

const std::array<BrowseType, 6> Table = {{
    {"_sftp-ssh._tcp", "sftp", ""},
    {"_ssh._tcp", "sftp", ""},
    {"_smb._tcp", "smb", ""},
    {"_webdav._tcp", "webdav", "http"},
    {"_webdavs._tcp", "webdav", "https"},
    {"_ftp._tcp", "ftp", ""},
}};

const QByteArray LocalSuffix = QByteArrayLiteral(".local");

QString cleanText(const QByteArray &bytes, int maxLength)
{
    const QString decoded = QString::fromUtf8(bytes);
    QString out;
    for (const QChar ch : decoded) {
        const ushort u = ch.unicode();
        const bool control = u < ControlLimit || (u >= C1First && u <= C1Last)
            || u == 0x2028 || u == 0x2029;
        if (!control)
            out.append(ch);
    }
    return out.left(maxLength).trimmed();
}

QString cleanPath(const QByteArray &bytes)
{
    QString p = cleanText(bytes, MaxPathLength);
    if (p.isEmpty())
        return p;
    if (!p.startsWith(QLatin1Char('/')))
        p.prepend(QLatin1Char('/'));
    return p;
}

bool hostByteAllowed(char c)
{
    const uchar u = static_cast<uchar>(c);
    return (u >= '0' && u <= '9') || (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z')
        || u == '-' || u == '_' || u >= 0x80;
}

// Host names go into URLs and connection parameters: only letters, digits,
// '-', '_' and UTF-8 are accepted; anything else (escapes, spaces, '/', '@',
// ':' ...) rejects the SRV record.
bool cleanHost(const QByteArray &target, QString *host)
{
    bool ok = false;
    const QList<QByteArray> labels = Dns::splitName(target, &ok);
    if (!ok || labels.isEmpty())
        return false;
    QByteArray joined;
    for (const QByteArray &label : labels) {
        if (!std::all_of(label.constBegin(), label.constEnd(), hostByteAllowed))
            return false;
        if (!joined.isEmpty())
            joined.append('.');
        joined.append(label);
    }
    if (joined.size() > MaxHostLength)
        return false;
    *host = QString::fromUtf8(joined);
    return true;
}

bool inSubnet(const QHostAddress &a, const char *net, int prefix)
{
    return a.isInSubnet(QHostAddress(QLatin1String(net)), prefix);
}

// An address worth connecting to. Link-local IPv6 needs an interface scope
// that a multicast DNS answer does not carry, so it is unusable here.
bool usableAddress(const QHostAddress &a)
{
    if (a.isNull() || a == QHostAddress::AnyIPv4 || a == QHostAddress::AnyIPv6)
        return false;
    if (a.protocol() == QAbstractSocket::IPv4Protocol)
        return !inSubnet(a, "224.0.0.0", Ipv4MulticastPrefix) && !inSubnet(a, "127.0.0.0", Ipv4LoopbackPrefix);
    return a != QHostAddress::LocalHostIPv6 && !inSubnet(a, "fe80::", Ipv6LinkLocalPrefix)
        && !inSubnet(a, "ff00::", Ipv6MulticastPrefix);
}

QByteArray typeSuffix(const BrowseType &t)
{
    return QByteArray(t.type) + LocalSuffix;
}

const BrowseType *browseTypeForName(const QByteArray &canonical)
{
    for (const BrowseType &t : Table) {
        if (typeSuffix(t) == canonical)
            return &t;
    }
    return nullptr;
}

// `target` must be "<one label>.<type>.local"; yields that label unescaped.
bool instanceLabel(const QByteArray &target, const QByteArray &typeName, QByteArray *label)
{
    const QByteArray canonical = Dns::canonicalName(target);
    const QByteArray suffix = "." + typeName;
    if (!canonical.endsWith(suffix) || canonical.size() == suffix.size())
        return false;
    bool ok = false;
    const QByteArray rest = target.left(target.size() - suffix.size());
    const QList<QByteArray> labels = Dns::splitName(rest, &ok);
    if (!ok || labels.size() != 1)
        return false;
    *label = labels.first();
    return true;
}

bool needsTxt(const BrowseType &t)
{
    const QByteArray p(t.provider);
    return p == "webdav" || p == "ftp";
}

bool sameContent(const DiscoveredService &a, const DiscoveredService &b)
{
    return a.instanceName == b.instanceName && a.serviceType == b.serviceType && a.provider == b.provider
        && a.tls == b.tls && a.host == b.host && a.port == b.port && a.path == b.path && a.user == b.user
        && a.addresses == b.addresses;
}

void consider(qint64 *best, qint64 t)
{
    if (t >= 0 && (*best < 0 || t < *best))
        *best = t;
}

} // namespace

const std::array<BrowseType, 6> &browseTypeTable()
{
    return Table;
}

const BrowseType *findBrowseType(const QString &serviceType)
{
    const QByteArray wanted = serviceType.toLatin1().toLower();
    for (const BrowseType &t : Table) {
        if (QByteArray(t.type) == wanted)
            return &t;
    }
    return nullptr;
}

void ServiceCache::Lifetime::set(qint64 now, quint32 ttlSeconds)
{
    received = now;
    ttlMs = static_cast<qint64>(std::min<quint32>(ttlSeconds, MaxTtlSeconds)) * MsPerSecond;
    stage = 0;
}

qint64 ServiceCache::Lifetime::refreshAt() const
{
    if (stage >= RefreshStages)
        return -1;
    return received + ttlMs * RefreshPercent[static_cast<size_t>(stage)] / PercentDivisor;
}

void ServiceCache::Collector::add(const QByteArray &name, quint16 type)
{
    const QPair<QByteArray, quint16> key(name, type);
    if (seen.contains(key))
        return;
    seen.insert(key);
    Dns::Question q;
    q.name = name;
    q.type = type;
    out.append(q);
}

// ---------------------------------------------------------------- ingest

void ServiceCache::ingest(const Dns::Message &message, qint64 now, const QDateTime &wall, Events *events)
{
    if (!message.isResponse() || message.opcode() != 0 || message.rcode() != 0)
        return;
    Context c;
    c.now = now;
    c.wall = wall;
    c.events = events;
    QVector<const Dns::Record *> records;
    for (const Dns::Record &r : message.answers)
        records.append(&r);
    for (const Dns::Record &r : message.additional)
        records.append(&r);
    // PTR first (creates instances), then what hangs off them.
    const std::array<quint16, 5> order = {{Dns::TypePtr, Dns::TypeSrv, Dns::TypeTxt, Dns::TypeA, Dns::TypeAaaa}};
    for (const quint16 type : order) {
        for (const Dns::Record *r : records) {
            if (r->type != type || r->cls != Dns::ClassIn)
                continue;
            switch (type) {
            case Dns::TypePtr: handlePtr(*r, &c); break;
            case Dns::TypeSrv: handleSrv(*r, &c); break;
            case Dns::TypeTxt: handleTxt(*r, &c); break;
            default: handleAddress(*r, &c); break;
            }
        }
    }
    finishContext(&c);
}

void ServiceCache::handlePtr(const Dns::Record &rec, Context *c)
{
    const QByteArray typeName = Dns::canonicalName(rec.name);
    const BrowseType *type = browseTypeForName(typeName);
    QByteArray label;
    if (!type || !instanceLabel(rec.target, typeName, &label))
        return;
    const QByteArray key = Dns::canonicalName(rec.target);
    if (rec.ttl == 0) {                             // RFC 6762 section 10.1: goodbye
        removeInstance(key, c);
        return;
    }
    auto it = m_instances.find(key);
    if (it == m_instances.end()) {
        if (m_instances.size() >= MaxInstances)
            return;
        Instance fresh;
        fresh.key = key;
        fresh.rawName = rec.target;
        fresh.label = label;
        fresh.type = type;
        it = m_instances.insert(key, fresh);
    }
    it.value().ptr.set(c->now, rec.ttl);
    it.value().lastSeen = c->wall;
    c->dirty.insert(key);
}

void ServiceCache::handleSrv(const Dns::Record &rec, Context *c)
{
    const QByteArray key = Dns::canonicalName(rec.name);
    auto it = m_instances.find(key);
    if (it == m_instances.end())
        return;
    if (rec.ttl == 0) {
        removeInstance(key, c);
        return;
    }
    QString host;
    if (rec.port == 0 || !cleanHost(rec.target, &host))     // RFC 2782: "." means "not available"
        return;
    Instance &inst = it.value();
    const QByteArray target = Dns::canonicalName(rec.target);
    if (!inst.hasSrv || inst.target != target) {
        if (!m_hosts.contains(target))                     // accept addresses for this host from now on
            m_hosts.insert(target, QVector<AddressEntry>());
        inst.attempts = 0;
        inst.gaveUp = false;
        inst.nextResolve = -1;
    }
    inst.hasSrv = true;
    inst.srv.set(c->now, rec.ttl);
    inst.target = target;
    inst.host = host;
    inst.port = rec.port;
    inst.lastSeen = c->wall;
    c->dirty.insert(key);
}

void ServiceCache::handleTxt(const Dns::Record &rec, Context *c)
{
    const QByteArray key = Dns::canonicalName(rec.name);
    auto it = m_instances.find(key);
    if (it == m_instances.end())
        return;
    Instance &inst = it.value();
    inst.hasTxt = true;
    inst.lastSeen = c->wall;
    if (rec.ttl == 0) {
        // A goodbye of the TXT record alone empties it for a second (RFC 6762
        // section 10.1); the service itself lives on with PTR and SRV.
        inst.txtStrings.clear();
        inst.txt.received = c->now;
        inst.txt.ttlMs = GoodbyeGraceMs;
        inst.txt.stage = RefreshStages;
    } else {
        inst.txtStrings = rec.txt;
        inst.txt.set(c->now, rec.ttl);
    }
    c->dirty.insert(key);
}

void ServiceCache::handleAddress(const Dns::Record &rec, Context *c)
{
    const QByteArray host = Dns::canonicalName(rec.name);
    auto it = m_hosts.find(host);
    if (it == m_hosts.end() || !usableAddress(rec.address))
        return;
    if (rec.cacheFlush && rec.ttl > 0)
        flushFamily(host, rec.type, c);
    QVector<AddressEntry> &entries = it.value();
    const auto found = std::find_if(entries.begin(), entries.end(),
                                    [&rec](const AddressEntry &e) { return e.address == rec.address; });
    if (rec.ttl == 0) {
        if (found != entries.end())
            entries.erase(found);
    } else if (found != entries.end()) {
        found->life.set(c->now, rec.ttl);
    } else if (entries.size() < MaxAddressesPerHost) {
        AddressEntry e;
        e.address = rec.address;
        e.life.set(c->now, rec.ttl);
        entries.append(e);
    }
    markHostDirty(host, c);
}

// RFC 6762 section 10.2: a cache-flush record replaces what was cached for that
// name and type, except for records received within the last second (they are
// part of the same answer).
void ServiceCache::flushFamily(const QByteArray &host, quint16 type, Context *c)
{
    const QPair<QByteArray, quint16> key(host, type);
    if (c->flushed.contains(key))
        return;
    c->flushed.insert(key);
    const QAbstractSocket::NetworkLayerProtocol family =
        type == Dns::TypeA ? QAbstractSocket::IPv4Protocol : QAbstractSocket::IPv6Protocol;
    QVector<AddressEntry> &entries = m_hosts[host];
    const qint64 cutoff = c->now - CacheFlushGraceMs;
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [family, cutoff](const AddressEntry &e) {
                                     return e.address.protocol() == family && e.life.received < cutoff;
                                 }),
                  entries.end());
}

void ServiceCache::markHostDirty(const QByteArray &host, Context *c)
{
    c->dirtyHosts.insert(host);
}

void ServiceCache::removeInstance(const QByteArray &key, Context *c)
{
    const auto it = m_instances.find(key);
    if (it == m_instances.end())
        return;
    if (it.value().announced) {
        Event e;
        e.kind = EventKind::Lost;
        e.service = it.value().last;
        c->events->append(e);
    }
    m_instances.erase(it);
    c->dirty.remove(key);
}

// ------------------------------------------------------------ evaluation

bool ServiceCache::hasAddresses(const QByteArray &host) const
{
    const auto it = m_hosts.constFind(host);
    return it != m_hosts.constEnd() && !it.value().isEmpty();
}

bool ServiceCache::isComplete(const Instance &inst) const
{
    return inst.hasSrv && hasAddresses(inst.target) && (inst.hasTxt || !needsTxt(*inst.type));
}

DiscoveredService ServiceCache::snapshot(const Instance &inst) const
{
    DiscoveredService s;
    s.instanceName = cleanText(inst.label, MaxTextLength);
    if (s.instanceName.isEmpty())
        s.instanceName = inst.host;
    s.serviceType = QString::fromLatin1(inst.type->type);
    s.provider = QString::fromLatin1(inst.type->provider);
    s.tls = QString::fromLatin1(inst.type->tls);
    s.host = inst.host;
    s.port = inst.port;
    if (needsTxt(*inst.type)) {
        s.path = cleanPath(Dns::txtValue(inst.txtStrings, "path"));
        s.user = cleanText(Dns::txtValue(inst.txtStrings, "u"), MaxTextLength);
    }
    QList<QHostAddress> v4;
    QList<QHostAddress> v6;
    for (const AddressEntry &e : m_hosts.value(inst.target))
        (e.address.protocol() == QAbstractSocket::IPv4Protocol ? v4 : v6).append(e.address);
    const auto byText = [](const QHostAddress &a, const QHostAddress &b) { return a.toString() < b.toString(); };
    std::sort(v4.begin(), v4.end(), byText);
    std::sort(v6.begin(), v6.end(), byText);
    s.addresses = v4 + v6;
    s.lastSeen = inst.lastSeen;
    return s;
}

void ServiceCache::evaluate(Instance *inst, Context *c)
{
    const bool complete = isComplete(*inst);
    if (complete) {
        inst->attempts = 0;
        inst->nextResolve = -1;
        inst->gaveUp = false;
    } else if (inst->nextResolve < 0 && inst->attempts == 0 && !inst->gaveUp) {
        inst->nextResolve = c->now;
    }
    // A service that was announced before and lost a record is not announced
    // again with less than it had.
    const bool ready = inst->hasSrv && (complete || (inst->gaveUp && !inst->everAnnounced));
    Event e;
    e.service = ready ? snapshot(*inst) : inst->last;
    if (ready && !inst->announced) {
        e.kind = EventKind::Found;
    } else if (ready && !sameContent(inst->last, e.service)) {
        e.kind = EventKind::Updated;
    } else if (!ready && inst->announced) {
        e.kind = EventKind::Lost;
    } else {
        inst->last.lastSeen = inst->lastSeen;
        return;
    }
    inst->announced = ready;
    inst->everAnnounced = inst->everAnnounced || ready;
    inst->last = e.service;
    c->events->append(e);
}

void ServiceCache::finishContext(Context *c)
{
    for (const QByteArray &host : std::as_const(c->dirtyHosts)) {
        for (auto it = m_instances.begin(); it != m_instances.end(); ++it) {
            if (it.value().hasSrv && it.value().target == host) {
                if (c->wall.isValid())          // expiry is not "seen"
                    it.value().lastSeen = c->wall;
                c->dirty.insert(it.key());
            }
        }
    }
    for (const QByteArray &key : std::as_const(c->dirty)) {
        const auto it = m_instances.find(key);
        if (it != m_instances.end())
            evaluate(&it.value(), c);
    }
    pruneHosts();
}

void ServiceCache::pruneHosts()
{
    QSet<QByteArray> used;
    for (const Instance &inst : std::as_const(m_instances)) {
        if (inst.hasSrv)
            used.insert(inst.target);
    }
    for (auto it = m_hosts.begin(); it != m_hosts.end();) {
        if (used.contains(it.key()))
            ++it;
        else
            it = m_hosts.erase(it);
    }
}

// ---------------------------------------------------------------- expiry

void ServiceCache::expireInstance(Instance *inst, Context *c)
{
    if (inst->ptr.expiresAt() <= c->now) {
        removeInstance(inst->key, c);
        return;
    }
    if (inst->hasSrv && inst->srv.expiresAt() <= c->now) {
        inst->hasSrv = false;
        inst->target.clear();
        inst->attempts = 0;
        inst->gaveUp = false;
        inst->nextResolve = -1;
        c->dirty.insert(inst->key);
    }
    if (inst->hasTxt && inst->txt.expiresAt() <= c->now) {
        inst->hasTxt = false;
        inst->txtStrings.clear();
        c->dirty.insert(inst->key);
    }
    const bool retriesExhausted = inst->attempts >= MaxResolveAttempts && inst->nextResolve >= 0
        && c->now >= inst->nextResolve;
    if (retriesExhausted && !isComplete(*inst)) {
        inst->gaveUp = true;
        inst->nextResolve = -1;
        c->dirty.insert(inst->key);
    }
}

void ServiceCache::expireAddresses(Context *c)
{
    for (auto it = m_hosts.begin(); it != m_hosts.end(); ++it) {
        QVector<AddressEntry> &entries = it.value();
        const qint64 now = c->now;
        const auto last = std::remove_if(entries.begin(), entries.end(),
                                         [now](const AddressEntry &e) { return e.life.expiresAt() <= now; });
        if (last != entries.end()) {
            entries.erase(last, entries.end());
            markHostDirty(it.key(), c);
        }
    }
}

void ServiceCache::expire(qint64 now, Events *events)
{
    Context c;
    c.now = now;
    c.events = events;
    const QList<QByteArray> keys = m_instances.keys();
    for (const QByteArray &key : keys) {
        const auto it = m_instances.find(key);
        if (it != m_instances.end())
            expireInstance(&it.value(), &c);
    }
    expireAddresses(&c);
    finishContext(&c);
}

// ------------------------------------------------------- questions, deadlines

void ServiceCache::collectResolve(Instance *inst, qint64 now, Collector *col)
{
    if (isComplete(*inst) || inst->nextResolve < 0 || now < inst->nextResolve
        || inst->attempts >= MaxResolveAttempts)
        return;
    if (!inst->hasSrv)
        col->add(inst->key, Dns::TypeSrv);
    if (needsTxt(*inst->type) && !inst->hasTxt)
        col->add(inst->key, Dns::TypeTxt);
    if (inst->hasSrv && !hasAddresses(inst->target)) {
        col->add(inst->target, Dns::TypeA);
        col->add(inst->target, Dns::TypeAaaa);
    }
    ++inst->attempts;
    inst->nextResolve = now + (static_cast<qint64>(FirstResolveDelayMs) << (inst->attempts - 1));
}

void ServiceCache::collectRefresh(Instance *inst, qint64 now, Collector *col)
{
    if (inst->hasSrv && inst->srv.refreshAt() >= 0 && now >= inst->srv.refreshAt()) {
        col->add(inst->key, Dns::TypeSrv);
        ++inst->srv.stage;
    }
    if (inst->hasTxt && inst->txt.refreshAt() >= 0 && now >= inst->txt.refreshAt()) {
        col->add(inst->key, Dns::TypeTxt);
        ++inst->txt.stage;
    }
}

void ServiceCache::collectHostRefresh(qint64 now, Collector *col)
{
    for (auto it = m_hosts.begin(); it != m_hosts.end(); ++it) {
        for (AddressEntry &e : it.value()) {
            if (e.life.refreshAt() < 0 || now < e.life.refreshAt())
                continue;
            const bool v4 = e.address.protocol() == QAbstractSocket::IPv4Protocol;
            col->add(it.key(), v4 ? Dns::TypeA : Dns::TypeAaaa);
            ++e.life.stage;
        }
    }
}

QVector<Dns::Question> ServiceCache::dueQuestions(qint64 now)
{
    Collector col;
    for (auto it = m_instances.begin(); it != m_instances.end(); ++it) {
        collectResolve(&it.value(), now, &col);
        collectRefresh(&it.value(), now, &col);
    }
    collectHostRefresh(now, &col);
    return col.out;
}

qint64 ServiceCache::instanceDeadline(const Instance &inst) const
{
    qint64 best = inst.ptr.expiresAt();
    if (inst.hasSrv) {
        consider(&best, inst.srv.expiresAt());
        consider(&best, inst.srv.refreshAt());
    }
    if (inst.hasTxt) {
        consider(&best, inst.txt.expiresAt());
        consider(&best, inst.txt.refreshAt());
    }
    if (!isComplete(inst))
        consider(&best, inst.nextResolve);
    return best;
}

qint64 ServiceCache::nextDeadline() const
{
    qint64 best = -1;
    for (const Instance &inst : std::as_const(m_instances))
        consider(&best, instanceDeadline(inst));
    for (const QVector<AddressEntry> &entries : std::as_const(m_hosts)) {
        for (const AddressEntry &e : entries) {
            consider(&best, e.life.expiresAt());
            consider(&best, e.life.refreshAt());
        }
    }
    return best;
}

QVector<Dns::Record> ServiceCache::knownAnswers(qint64 now) const
{
    QVector<Dns::Record> out;
    for (const Instance &inst : std::as_const(m_instances)) {
        const qint64 remaining = inst.ptr.expiresAt() - now;
        if (remaining * 2 < inst.ptr.ttlMs)
            continue;
        Dns::Record r;
        r.name = typeSuffix(*inst.type);
        r.type = Dns::TypePtr;
        r.ttl = static_cast<quint32>(std::max<qint64>(1, remaining / MsPerSecond));
        r.target = inst.rawName;
        out.append(r);
    }
    return out;
}

QVector<DiscoveredService> ServiceCache::services() const
{
    QVector<DiscoveredService> out;
    for (const Instance &inst : std::as_const(m_instances)) {
        if (inst.announced)
            out.append(inst.last);
    }
    return out;
}

void ServiceCache::clear()
{
    m_instances.clear();
    m_hosts.clear();
}

} // namespace NetVfs
