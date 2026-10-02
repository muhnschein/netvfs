// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERYCACHE_H
#define NETVFS_DISCOVERYCACHE_H

#include "discovery.h"
#include "dnsmessage.h"

#include <QtCore/QHash>
#include <QtCore/QPair>
#include <QtCore/QSet>

#include <array>

// Internal to the core library (not installed): the record cache and resolver
// state machine behind Discovery. No sockets, no timers, no clock: every call
// gets `now` (monotonic milliseconds), so it is testable through Discovery with
// a fake clock and transport. SPEC-v2 XD-2.
namespace NetVfs {

struct BrowseType {
    const char *type;        // "_sftp-ssh._tcp"
    const char *provider;    // "sftp"
    const char *tls;         // "http"/"https" for webdav; "" otherwise
};

const std::array<BrowseType, 6> &browseTypeTable();
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
    static constexpr int MaxTtlSeconds = 7200;          // longer TTLs are clamped
    // A record that is not answered after this many queries makes the service
    // appear with what is known (host and port without addresses or TXT).
    static constexpr int MaxResolveAttempts = 3;
    static constexpr int FirstResolveDelayMs = 1000;
    // RFC 6762 section 5.2: refresh queries at 80, 90 and 95 percent of the TTL.
    static constexpr int RefreshStages = 3;

    // Applies a received message. Messages that are not plain responses are
    // ignored (RFC 6762 section 18.3, 18.11).
    void ingest(const Dns::Message &message, qint64 now, const QDateTime &wall, Events *events);
    // Drops what expired, gives up resolving what stayed unanswered.
    void expire(qint64 now, Events *events);
    // Earliest monotonic time at which expire() or dueQuestions() has work;
    // -1 if none.
    qint64 nextDeadline() const;
    // Follow-up questions that are due (missing SRV/TXT/address records, TTL
    // refresh at 80/90/95 percent). Advances the retry state.
    QVector<Dns::Question> dueQuestions(qint64 now);
    // PTR records for known-answer suppression (RFC 6762 section 7.1): those
    // with more than half of their TTL left.
    QVector<Dns::Record> knownAnswers(qint64 now) const;
    QVector<DiscoveredService> services() const;
    void clear();

private:
    struct Lifetime {
        qint64 received = 0;
        qint64 ttlMs = 0;
        int stage = 0;               // refresh queries sent so far
        void set(qint64 now, quint32 ttlSeconds);
        qint64 expiresAt() const { return received + ttlMs; }
        qint64 refreshAt() const;    // -1 when all stages are used
    };

    struct AddressEntry {
        QHostAddress address;
        Lifetime life;

        AddressEntry() = default;
        AddressEntry(const AddressEntry &other) = default;
        AddressEntry &operator=(const AddressEntry &other) = default;
        ~AddressEntry() = default;
        // QHostAddress has no move constructor in Qt 5: swapping it cannot fail.
        AddressEntry(AddressEntry &&other) noexcept : life(other.life) { address.swap(other.address); }
        AddressEntry &operator=(AddressEntry &&other) noexcept
        {
            address.swap(other.address);
            life = other.life;
            return *this;
        }
    };

    struct Instance {
        QByteArray key;              // canonical full name
        QByteArray rawName;          // full name as received, for known answers
        QByteArray label;            // unescaped instance label
        const BrowseType *type = nullptr;
        Lifetime ptr;
        bool hasSrv = false;
        Lifetime srv;
        QByteArray target;           // canonical SRV target
        QString host;
        int port = 0;
        bool hasTxt = false;
        Lifetime txt;
        QList<QByteArray> txtStrings;
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
        QSet<QByteArray> dirty;          // instance keys to re-evaluate
        QSet<QByteArray> dirtyHosts;     // canonical host names whose addresses changed
        QSet<QPair<QByteArray, quint16>> flushed;
    };

    struct Collector {
        QVector<Dns::Question> out;
        QSet<QPair<QByteArray, quint16>> seen;
        void add(const QByteArray &name, quint16 type);
    };

    void handlePtr(const Dns::Record &rec, Context *c);
    void handleSrv(const Dns::Record &rec, Context *c);
    void handleTxt(const Dns::Record &rec, Context *c);
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
    QHash<QByteArray, QVector<AddressEntry>> m_hosts;   // targets of known instances only
};

} // namespace NetVfs

#endif
