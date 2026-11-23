// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_WIRECONNECTION_H
#define NETVFS_TEST_WIRECONNECTION_H

#ifndef Q_MOC_RUN
#include "wire.h"
#endif

#include <QtCore/QObject>

#include <functional>
#include <memory>

struct DBusConnection;

namespace NetVfs {
namespace BridgeTest {
class WireConnection : public QObject
{
    Q_OBJECT
public:
    using Handler = std::function<void(DBusMessage *message)>;

    static WireConnection *connectTo(const QString &address, Result *result, QObject *parent = nullptr);

    explicit WireConnection(DBusConnection *connection, QObject *parent = nullptr);
    ~WireConnection() override;

    void setHandler(const Handler &handler) { m_handler = handler; }

    bool isConnected() const;
    bool isAuthenticated() const;
    bool canPassUnixFds() const;

    quint32 send(MessagePtr message);
    void close();

    struct Integration;

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

}
}

#endif
