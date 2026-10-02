// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_WIRECONNECTION_H
#define NETVFS_BRIDGE_WIRECONNECTION_H

#include "wire.h"

#include <QtCore/QObject>

#include <functional>

struct DBusConnection;
struct DBusServer;

namespace NetVfs {
namespace Bridge {

// One peer-to-peer D-Bus connection (libdbus), driven by the Qt event loop of
// the thread that created it. Not thread-safe: use it from that thread only.
class WireConnection : public QObject
{
    Q_OBJECT
public:
    // Every incoming message (method calls, replies, errors, signals) except
    // org.freedesktop.DBus.Local.Disconnected, which ends the connection
    // (disconnected()). Return value ignored; libdbus answers Peer.Ping itself.
    using Handler = std::function<void(DBusMessage *message)>;

    // Client side (tests, tools): connects to `address` ("unix:path=...").
    static WireConnection *connectTo(const QString &address, Result *result, QObject *parent = nullptr);

    // Takes a new reference on `connection` and integrates it into the event loop.
    WireConnection(DBusConnection *connection, QObject *parent = nullptr);
    ~WireConnection() override;

    void setHandler(const Handler &handler) { m_handler = handler; }

    bool isConnected() const;
    bool isAuthenticated() const;
    bool canPassUnixFds() const;
    // The connected socket (for SO_PEERCRED), -1 if unknown.
    int socketFd() const;
    // Bytes queued for sending (flow control for streamed signals).
    qint64 outgoingBytes() const;

    // Queues `message` (consumed); returns its serial, 0 on failure.
    quint32 send(MessagePtr message);
    // Closes the connection without sending anything else; disconnected()
    // follows from the event loop.
    void close();

    DBusConnection *handle() const { return m_connection; }

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
    Handler m_handler;
    bool m_dispatchScheduled = false;
    bool m_disconnected = false;
};

// Listening side: dbus_server_listen() on an address, "systemd:" for the
// socket systemd passed (XB-2, sd_listen_fds protocol implemented by libdbus).
// Authentication is EXTERNAL only, and libdbus accepts only the bridge's own
// uid (no root, no anonymous).
class WireServer : public QObject
{
    Q_OBJECT
public:
    explicit WireServer(QObject *parent = nullptr);
    ~WireServer() override;

    Result listen(const QString &address);
    bool isListening() const { return m_server != nullptr; }
    QString address() const;
    void stop();

    struct Integration;   // libdbus main loop glue (wireconnection.cpp)

Q_SIGNALS:
    // Not yet authenticated; no message has been dispatched yet. The receiver
    // takes ownership (or deletes it to refuse the client).
    void newConnection(NetVfs::Bridge::WireConnection *connection);

private:
    friend struct Integration;
    DBusServer *m_server = nullptr;
};

} // namespace Bridge
} // namespace NetVfs

#endif
