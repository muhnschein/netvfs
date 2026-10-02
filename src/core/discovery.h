// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_DISCOVERY_H
#define NETVFS_DISCOVERY_H

#include "netvfs_global.h"
#include "types.h"

#include <QtCore/QDateTime>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtCore/QVector>
#include <QtNetwork/QHostAddress>

// SPEC-v2 section 7 (XD-1..XD-3, XD-5): finding file servers on the local network.
//
// NetVfs::Discovery is a minimal DNS-SD browser (RFC 6763 over multicast DNS,
// RFC 6762) without any dependency on avahi. It asks for the service types
//
//     _sftp-ssh._tcp  _ssh._tcp  -> provider "sftp"
//     _smb._tcp                  -> provider "smb"
//     _webdav._tcp               -> provider "webdav", tls "http"
//     _webdavs._tcp              -> provider "webdav", tls "https"
//     _ftp._tcp                  -> provider "ftp"
//
// resolves every instance (SRV, TXT, A, AAAA) and reports it as a
// DiscoveredService.
//
// Usage (main thread only; the object lives on, and must be used from, the
// thread that created it):
//
//     auto *discovery = new NetVfs::Discovery(this);
//     connect(discovery, &NetVfs::Discovery::found, this, &Model::add);
//     connect(discovery, &NetVfs::Discovery::updated, this, &Model::change);
//     connect(discovery, &NetVfs::Discovery::lost, this, &Model::remove);
//     discovery->start();            // when the first consumer wants results
//     ...
//     discovery->stop();             // when the last one goes away
//
// XD-5: it runs only while a consumer asked for it. start() and stop() are
// reference counted; the sockets are opened on the first start() and closed,
// the timers stopped and the result cache dropped on the matching last stop().
// Nothing is sent or received while stopped.
//
// XD-3: Discovery never connects to anything. It sends and receives mDNS
// datagrams and nothing else. What it hands out are templates:
// toConnectionParams() turns a result into ConnectionParams for the user to
// confirm and complete (password, host key); no secret is ever taken from the
// network (a TXT "p=" key is ignored).
//
// Everything received is untrusted input from the local network: records are
// parsed defensively (dnsmessage.h), names and TXT values are sanitised, and
// the number of tracked instances and addresses is bounded.
namespace NetVfs {

class DiscoveryTransport;

// One server found on the network. For SMB `host` and `port` are the SRV
// target and port and the share is left for the user to pick (server mode,
// SPEC-v2 XM-2).
struct NETVFS_EXPORT DiscoveredService {
    QString instanceName;               // "My NAS" (first label of the instance name, UTF-8)
    QString serviceType;                // "_smb._tcp"
    QString provider;                   // "sftp" | "smb" | "webdav" | "ftp"
    QString tls;                        // webdav: "https" (_webdavs) or "http" (_webdav); else empty
    QString host;                       // SRV target without the trailing dot, e.g. "nas.local"
    int port = 0;
    QString path;                       // TXT "path=" (webdav, ftp), starts with '/'; else empty
    QString user;                       // TXT "u=" (webdav, ftp); else empty
    QList<QHostAddress> addresses;      // A and AAAA of `host`, IPv4 first, never link-local IPv6
    QDateTime lastSeen;                 // UTC, last time any record of this service arrived

    // Identity of the announcement (lower-cased instance and service type); a
    // service keeps its key across updated() signals.
    QString key() const;
    // Identity of the endpoint: provider, host and port. The same machine
    // announcing both _ssh._tcp and _sftp-ssh._tcp yields two services with
    // equal endpointKey(); a consumer that lists servers should merge them.
    QString endpointKey() const;
};

// Mapping of a DNS-SD service type ("_webdavs._tcp") to provider and tls
// option. Returns false for types Discovery does not browse.
NETVFS_EXPORT bool providerForServiceType(const QString &serviceType, QString *provider,
                                          QString *tls = nullptr);
// The six service types in browse order.
NETVFS_EXPORT QStringList browsedServiceTypes();

// XD-3: connection template for a result.
//   provider            as in the result
//   host                SRV target; the first address when the target is empty
//   port                the SRV port (explicit, even when it is the default)
//   username            TXT "u=" or empty
//   options             webdav: "tls" ("https"/"http"), "base_path" (TXT path, default "/");
//                       "allow_insecure" is NOT set: plain http needs the user's consent
//                       (SPEC-v2 W-2). smb: no "share" (server mode).
// `*locationPath`, when not null, receives the location path below the
// connection root to start browsing at: "/", or for ftp the TXT path.
// No password, no host key: the caller must run the identity check (XC-16)
// before any credential is sent.
NETVFS_EXPORT ConnectionParams toConnectionParams(const DiscoveredService &service,
                                                  QString *locationPath = nullptr);

// Time source, injectable for tests. Not owned by Discovery.
class NETVFS_EXPORT DiscoveryClock
{
public:
    virtual ~DiscoveryClock();
    virtual qint64 monotonicMs() const;        // for TTLs and scheduling
    virtual QDateTime wallTime() const;        // UTC, for DiscoveredService::lastSeen
};

class NETVFS_EXPORT Discovery : public QObject
{
    Q_OBJECT

public:
    // Backoff of the browse queries (RFC 6762 section 5.2): the gap after the
    // n-th query (n = 0 for the first) is 1 s, 2 s, 4 s, ... at most 60 s.
    static constexpr int FirstQueryIntervalMs = 1000;
    static constexpr int MaxQueryIntervalMs = 60000;
    static int queryIntervalMs(int n);

    // Multicast UDP on port 5353 (IPv4 and, when available, IPv6) on all
    // suitable interfaces.
    explicit Discovery(QObject *parent = nullptr);
    // Own transport (tests, other platforms); takes ownership.
    explicit Discovery(DiscoveryTransport *transport, QObject *parent = nullptr);
    ~Discovery() override;

    // Reference counted (XD-5). The first start() opens the sockets and sends
    // the first query at once; returns false if no socket could be opened (the
    // consumer count still increases and opening is retried with every
    // scheduled query, so a network that comes up later is picked up).
    // Every start() must be paired with one stop(); extra stop() calls are ignored.
    bool start();
    void stop();
    bool isRunning() const { return m_consumers > 0; }
    int consumers() const { return m_consumers; }

    // Asks again now and restarts the backoff, for a "refresh" button.
    void refresh();

    // Services that are currently announced (found and not yet lost).
    QVector<DiscoveredService> services() const;

    // Test seam: the clock (nullptr restores the system clock) and the timer
    // pass that the internal single-shot timer runs; with a fake clock a test
    // advances it and calls runTimers().
    void setClock(const DiscoveryClock *clock);
    void runTimers();

signals:
    // A service is complete (host, port and, once resolved or after the
    // resolution attempts ran out, addresses and TXT data).
    void found(const NetVfs::DiscoveredService &service);
    // A published field changed (host, port, path, user, addresses). A mere
    // refresh of the TTLs does not emit.
    void updated(const NetVfs::DiscoveredService &service);
    // The service said goodbye (TTL 0) or its records expired. Carries the last
    // known state.
    void lost(const NetVfs::DiscoveredService &service);

private:
    class Private;
    QScopedPointer<Private> d;
    int m_consumers = 0;

    Q_DISABLE_COPY(Discovery)
};

// Datagram transport under Discovery. The default is UDP multicast
// (discoverytransport.h); tests substitute a fake.
class NETVFS_EXPORT DiscoveryTransport : public QObject
{
    Q_OBJECT

public:
    explicit DiscoveryTransport(QObject *parent = nullptr) : QObject(parent) {}
    // Binds the sockets; true if at least one family is usable. Called again
    // after a failure. Idempotent while open.
    virtual bool open() = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;
    // Sends one datagram to the mDNS group on every joined interface.
    virtual void send(const QByteArray &datagram) = 0;

signals:
    // `sender` has already been checked by the transport to be on-link and the
    // datagram to come from the mDNS port; Discovery re-validates the content.
    void datagramReceived(const QByteArray &datagram, const QHostAddress &sender);
};

} // namespace NetVfs

Q_DECLARE_METATYPE(NetVfs::DiscoveredService)

#endif
