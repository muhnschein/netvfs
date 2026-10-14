// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_WIRECONNECTION_H
#define NETVFS_TEST_WIRECONNECTION_H

// The moc of Qt 5.6 (Sailfish SDK) cannot parse C++17 nested namespaces; it
// does not need the headers that have them.
#ifndef Q_MOC_RUN
#include "wire.h"
#endif

#include <QtCore/QObject>

#include <functional>
#include <memory>

struct DBusConnection;

namespace NetVfs {
namespace BridgeTest {

// One peer-to-peer D-Bus connection to the bridge (libdbus), driven by the Qt
// event loop of the thread that created it. Not thread-safe: use it from that
// thread only.
class WireConnection : public QObject
{
    Q_OBJECT
public:
    // Every incoming message (method calls, replies, errors, signals) except
    // org.freedesktop.DBus.Local.Disconnected, which ends the connection
    // (disconnected()). Return value ignored; libdbus answers Peer.Ping itself.
    using Handler = std::function<void(DBusMessage *message)>;

    // Connects to `address` ("unix:path=...").
    static WireConnection *connectTo(const QString &address, Result *result, QObject *parent = nullptr);

    // Takes a new reference on `connection` and integrates it into the event loop.
    explicit WireConnection(DBusConnection *connection, QObject *parent = nullptr);
    ~WireConnection() override;

    void setHandler(const Handler &handler) { m_handler = handler; }

    bool isConnected() const;
    bool isAuthenticated() const;
    bool canPassUnixFds() const;

    // Queues `message` (consumed); returns its serial, 0 on failure.
    quint32 send(MessagePtr message);
    // Closes the connection without sending anything else; disconnected()
    // follows from the event loop.
    void close();

    struct Integration;   // libdbus main loop glue (wireconnection.cpp)

Q_SIGNALS:
    void disconnected();

private:
    friend struct Integration;
    void scheduleDispatch();
    void dispatch();
    void handle(DBusMessage *message);
    void noteDisconnected();

    DBusConnection *m_connection = nullptr;
    std::unique_ptr<Integration> m_integration;
    Handler m_handler;
    bool m_dispatchScheduled = false;
    bool m_disconnected = false;
};

} // namespace BridgeTest
} // namespace NetVfs

#endif
