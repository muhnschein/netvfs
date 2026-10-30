// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERYCACHE_H
#define NETVFS_DISCOVERYCACHE_H

#include "discovery.h"
#include "dnsmessage.h"

#include <QtCore/QHash>
#include <QtCore/QPair>
#include <QtCore/QSet>

#include <array>

// Internal. Record cache and resolver state machine behind Discovery. No sockets, timers, clock:
// every call gets `now` (monotonic ms).
namespace NetVfs {

struct BrowseType {
    const char *type;
    const char *provider;
};

const std::array<BrowseType, 3> &browseTypeTable();
const BrowseType *findBrowseType(const QString &serviceType);

class ServiceCache
{
public:
    enum class EventKind { Found, Updated, Lost };
    struct Event {
        EventKind kind = EventKind::Found;
        DiscoveredService service;
    };
    using Events = QVector<Event>;

    // Bounds on what an untrusted network can make us hold.
    static constexpr int MaxInstances = 256;
    static constexpr int MaxAddressesPerHost = 8;
    static constexpr int MaxTtlSeconds = 7200;
    // Unanswered after this many queries: service appears with what is known.
    static constexpr int MaxResolveAttempts = 3;
    static constexpr int FirstResolveDelayMs = 1000;
    // RFC 6762 section 5.2: refresh at 80, 90, 95 percent of TTL.
    static constexpr int RefreshStages = 3;

    // Non-response messages ignored (RFC 6762 section 18.3, 18.11).
    void ingest(const Dns::Message &message, qint64 now, const QDateTime &wall, Events *events);
    void expire(qint64 now, Events *events);
    qint64 nextDeadline() const;
    QVector<Dns::Question> dueQuestions(qint64 now);
    // Known-answer suppression PTRs: more than half TTL left.
    QVector<Dns::Record> knownAnswers(qint64 now) const;
    QVector<DiscoveredService> services() const;
    void clear();

private:
    struct Lifetime {
        qint64 received = 0;
        qint64 ttlMs = 0;
        int stage = 0;
        void set(qint64 now, quint32 ttlSeconds);
        qint64 expiresAt() const { return received + ttlMs; }
        qint64 refreshAt() const;
    };

    struct AddressEntry {
        QHostAddress address;
        Lifetime life;

        // Qt 5 QHostAddress has no move ctor; Qt aborts on alloc failure, so moves are noexcept in
        // effect.
        AddressEntry() = default;
        AddressEntry(const AddressEntry &other) = default;
        AddressEntry &operator=(const AddressEntry &other) = default;
        AddressEntry(AddressEntry &&other) noexcept = default;
        AddressEntry &operator=(AddressEntry &&other) noexcept = default;
        ~AddressEntry() = default;
    };

    struct Instance {
        QByteArray key;
        QByteArray rawName;
        QByteArray label;
        const BrowseType *type = nullptr;
        Lifetime ptr;
        bool hasSrv = false;
        Lifetime srv;
        QByteArray target;
        QString host;
        int port = 0;
        int attempts = 0;
        qint64 nextResolve = -1;
        bool gaveUp = false;
        bool announced = false;
        bool everAnnounced = false;
        DiscoveredService last;
        QDateTime lastSeen;
    };

    struct Context {
        qint64 now = 0;
        QDateTime wall;
        Events *events = nullptr;
        QSet<QByteArray> dirty;
        QSet<QByteArray> dirtyHosts;
        QSet<QPair<QByteArray, quint16>> flushed;
    };

    struct Collector {
        QVector<Dns::Question> out;
        QSet<QPair<QByteArray, quint16>> seen;
        void add(const QByteArray &name, quint16 type);
    };

    void handlePtr(const Dns::Record &rec, Context *c);
    void handleSrv(const Dns::Record &rec, Context *c);
    void handleAddress(const Dns::Record &rec, Context *c);
    void flushFamily(const QByteArray &host, quint16 type, Context *c);
    void markHostDirty(const QByteArray &host, Context *c) const;
    void removeInstance(const QByteArray &key, Context *c);
    void evaluate(Instance *inst, Context *c) const;
    void finishContext(Context *c);
    void touchInstancesOf(const QByteArray &host, Context *c);
    void expireInstance(Instance *inst, Context *c);
    void expireAddresses(Context *c);
    void pruneHosts();

    bool isComplete(const Instance &inst) const;
    bool hasAddresses(const QByteArray &host) const;
    DiscoveredService snapshot(const Instance &inst) const;
    void collectResolve(Instance *inst, qint64 now, Collector *col) const;
    void collectRefresh(Instance *inst, qint64 now, Collector *col) const;
    void collectHostRefresh(qint64 now, Collector *col);
    qint64 instanceDeadline(const Instance &inst) const;

    QHash<QByteArray, Instance> m_instances;
    QHash<QByteArray, QVector<AddressEntry>> m_hosts;
};

}
#endif
