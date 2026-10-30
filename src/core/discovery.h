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

// Minimal DNS-SD browser (RFC 6763 over RFC 6762 mDNS), no avahi. Browses _sftp-ssh._tcp and
// _ssh._tcp (provider "sftp"), _smb._tcp (provider "smb"). Main thread only.
// start()/stop() are reference counted: sockets open on first start(), close on last stop();
// stopped = no traffic.
// Never connects. Results are templates for the user to confirm; no secret from the network. All
// input untrusted: parsed defensively, names sanitised, instance and address counts bounded.
namespace NetVfs {

class DiscoveryTransport;

// For SMB `host`/`port` are SRV target and port; share left to the user.
struct NETVFS_EXPORT DiscoveredService {
    QString instanceName;
    QString serviceType;
    QString provider;
    QString host;
    int port = 0;
    QList<QHostAddress> addresses;
    QDateTime lastSeen;

    QString key() const;
    QString endpointKey() const;
};

// false for types Discovery does not browse.
NETVFS_EXPORT bool providerForServiceType(const QString &serviceType, QString *provider);
NETVFS_EXPORT QStringList browsedServiceTypes();

// Connection template: host = SRV target (first address when empty), port explicit, no options. No
// credentials: caller must run the identity check before sending any.
NETVFS_EXPORT ConnectionParams toConnectionParams(const DiscoveredService &service);

// Not owned.
class NETVFS_EXPORT DiscoveryClock
{
public:
    virtual ~DiscoveryClock();
    virtual qint64 monotonicMs() const;
    virtual QDateTime wallTime() const;
};

class NETVFS_EXPORT Discovery : public QObject
{
    Q_OBJECT

public:
    // Browse query backoff (RFC 6762 section 5.2): 1 s, 2 s, 4 s, ... max 60 s.
    static constexpr int FirstQueryIntervalMs = 1000;
    static constexpr int MaxQueryIntervalMs = 60000;
    static int queryIntervalMs(int n);

    // Multicast UDP 5353, IPv4 and IPv6 if available.
    explicit Discovery(QObject *parent = nullptr);
    // Takes ownership.
    explicit Discovery(DiscoveryTransport *transport, QObject *parent = nullptr);
    ~Discovery() override;

    // First start() opens sockets and queries; false if none opened (still counted, retried with
    // each query). Pair with stop(); extra stop() ignored.
    bool start();
    void stop();
    bool isRunning() const { return m_consumers > 0; }
    int consumers() const { return m_consumers; }

    void refresh();

    QVector<DiscoveredService> services() const;

    // Test seam: clock (nullptr = system) and timer pass; tests advance a fake clock and call
    // runTimers().
    void setClock(const DiscoveryClock *clock);
    void runTimers();

signals:
    // Complete: host, port, and addresses/TXT once resolved or attempts ran out.
    void found(const NetVfs::DiscoveredService &service);
    // A published field changed. TTL refresh alone does not emit.
    void updated(const NetVfs::DiscoveredService &service);
    // Goodbye (TTL 0) or expiry. Carries last known state.
    void lost(const NetVfs::DiscoveredService &service);

private:
    class Private;
    QScopedPointer<Private> d;
    int m_consumers = 0;

    Q_DISABLE_COPY(Discovery)
};

// Datagram transport under Discovery.
class NETVFS_EXPORT DiscoveryTransport : public QObject
{
    Q_OBJECT

public:
    using QObject::QObject;
    // True if at least one family is usable. Idempotent while open.
    virtual bool open() = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;
    virtual void send(const QByteArray &datagram) = 0;

signals:
    // `sender` already checked on-link and from the mDNS port; Discovery re-validates content.
    void datagramReceived(const QByteArray &datagram, const QHostAddress &sender);
};

}
Q_DECLARE_METATYPE(NetVfs::DiscoveredService)

#endif
