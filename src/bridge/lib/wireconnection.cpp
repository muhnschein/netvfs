// SPDX-License-Identifier: LGPL-2.1-or-later
#include "wireconnection.h"

#include <QtCore/QPointer>
#include <QtCore/QSocketNotifier>
#include <QtCore/QTimer>

#include <dbus/dbus.h>

#include <array>
#include <unistd.h>

namespace NetVfs {
namespace Bridge {

namespace {

// XB-17 sizes: no inbound call needs more than a few KiB (the largest is
// ConnectAdHoc); Upload and Download carry exactly one fd.
constexpr long MaxInboundMessageBytes = 1 << 20;
constexpr long MaxInboundQueuedBytes = 8 << 20;
constexpr long MaxInboundMessageFds = 2;
constexpr long MaxInboundQueuedFds = 8;

// Read and write notifiers of one DBusWatch. Owned through the watch data;
// deleted later because removal may happen inside its own activation.
class WatchNotifier : public QObject
{
public:
    WatchNotifier(DBusWatch *watch, std::function<void()> afterHandle)
        : m_watch(watch), m_afterHandle(std::move(afterHandle))
    {
        const int fd = dbus_watch_get_unix_fd(watch);
        const unsigned int flags = dbus_watch_get_flags(watch);
        if (flags & DBUS_WATCH_READABLE) {
            m_read = new QSocketNotifier(fd, QSocketNotifier::Read, this);
            QObject::connect(m_read, &QSocketNotifier::activated, this, [this]() { handle(DBUS_WATCH_READABLE); });
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            m_write = new QSocketNotifier(fd, QSocketNotifier::Write, this);
            QObject::connect(m_write, &QSocketNotifier::activated, this, [this]() { handle(DBUS_WATCH_WRITABLE); });
        }
        toggle();
    }

    void toggle()
    {
        const bool enabled = m_watch && dbus_watch_get_enabled(m_watch);
        if (m_read)
            m_read->setEnabled(enabled);
        if (m_write)
            m_write->setEnabled(enabled);
    }

    void detach()
    {
        m_watch = nullptr;
        toggle();
        deleteLater();
    }

private:
    void handle(unsigned int flags)
    {
        if (!m_watch)
            return;
        dbus_watch_handle(m_watch, flags);
        if (m_afterHandle)
            m_afterHandle();
    }

    DBusWatch *m_watch;
    std::function<void()> m_afterHandle;
    QSocketNotifier *m_read = nullptr;
    QSocketNotifier *m_write = nullptr;
};

class TimeoutTimer : public QTimer
{
public:
    explicit TimeoutTimer(DBusTimeout *timeout) : m_timeout(timeout)
    {
        setSingleShot(false);
        QObject::connect(this, &QTimer::timeout, this, [this]() {
            if (m_timeout)
                dbus_timeout_handle(m_timeout);
        });
        toggle();
    }

    void toggle()
    {
        if (m_timeout && dbus_timeout_get_enabled(m_timeout))
            start(dbus_timeout_get_interval(m_timeout));
        else
            stop();
    }

    void detach()
    {
        m_timeout = nullptr;
        stop();
        deleteLater();
    }

private:
    DBusTimeout *m_timeout;
};

// libdbus callbacks shared by connections and servers. `afterHandle` runs
// after every watch activation (a connection schedules a dispatch).
template <typename Owner>
struct LoopCallbacks {
    static dbus_bool_t addWatch(DBusWatch *watch, void *data)
    {
        auto *owner = static_cast<Owner *>(data);
        auto *notifier = new WatchNotifier(watch, [owner]() { owner->afterWatch(); });
        dbus_watch_set_data(watch, notifier, nullptr);
        return TRUE;
    }
    static void removeWatch(DBusWatch *watch, void *)
    {
        if (auto *notifier = static_cast<WatchNotifier *>(dbus_watch_get_data(watch)))
            notifier->detach();
        dbus_watch_set_data(watch, nullptr, nullptr);
    }
    static void toggleWatch(DBusWatch *watch, void *)
    {
        if (auto *notifier = static_cast<WatchNotifier *>(dbus_watch_get_data(watch)))
            notifier->toggle();
    }
    static dbus_bool_t addTimeout(DBusTimeout *timeout, void *)
    {
        dbus_timeout_set_data(timeout, new TimeoutTimer(timeout), nullptr);
        return TRUE;
    }
    static void removeTimeout(DBusTimeout *timeout, void *)
    {
        if (auto *timer = static_cast<TimeoutTimer *>(dbus_timeout_get_data(timeout)))
            timer->detach();
        dbus_timeout_set_data(timeout, nullptr, nullptr);
    }
    static void toggleTimeout(DBusTimeout *timeout, void *)
    {
        if (auto *timer = static_cast<TimeoutTimer *>(dbus_timeout_get_data(timeout)))
            timer->toggle();
    }
};

bool isLocalDisconnected(DBusMessage *message)
{
    return dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected");
}

// XB-5 first line: only the bridge's own uid authenticates (libdbus would
// otherwise also accept root).
dbus_bool_t allowOwnUidOnly(DBusConnection *, unsigned long uid, void *)
{
    return uid == static_cast<unsigned long>(::geteuid()) ? TRUE : FALSE;
}

} // namespace

// -------------------------------------------------------------- connection

struct WireConnection::Integration {
    WireConnection *owner;
    void afterWatch() const { owner->scheduleDispatch(); }

    static DBusHandlerResult filter(DBusConnection *, DBusMessage *message, void *data)
    {
        static_cast<WireConnection *>(data)->handle(message);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    static void dispatchStatus(DBusConnection *, DBusDispatchStatus status, void *data)
    {
        if (status == DBUS_DISPATCH_DATA_REMAINS)
            static_cast<WireConnection *>(data)->scheduleDispatch();
    }
};

namespace {
using ConnectionLoop = LoopCallbacks<WireConnection::Integration>;
}

WireConnection *WireConnection::connectTo(const QString &address, Result *result, QObject *parent)
{
    DBusError error;
    dbus_error_init(&error);
    DBusConnection *connection = dbus_connection_open_private(address.toUtf8().constData(), &error);
    if (!connection) {
        if (result) {
            *result = Result(Error::NetworkUnreachable,
                             QStringLiteral("Cannot connect: %1").arg(QString::fromUtf8(error.message)));
        }
        dbus_error_free(&error);
        return nullptr;
    }
    auto *wire = new WireConnection(connection, parent);
    dbus_connection_unref(connection);   // the WireConnection holds its own reference
    if (result)
        *result = Result::success();
    return wire;
}

WireConnection::WireConnection(DBusConnection *connection, QObject *parent)
    : QObject(parent)
    , m_connection(dbus_connection_ref(connection))
{
    auto *integration = new Integration{ this };
    dbus_connection_set_exit_on_disconnect(m_connection, FALSE);
    dbus_connection_set_watch_functions(m_connection, ConnectionLoop::addWatch, ConnectionLoop::removeWatch,
                                        ConnectionLoop::toggleWatch, integration,
                                        [](void *data) { delete static_cast<Integration *>(data); });
    dbus_connection_set_timeout_functions(m_connection, ConnectionLoop::addTimeout, ConnectionLoop::removeTimeout,
                                          ConnectionLoop::toggleTimeout, nullptr, nullptr);
    dbus_connection_set_dispatch_status_function(m_connection, Integration::dispatchStatus, this, nullptr);
    dbus_connection_add_filter(m_connection, Integration::filter, this, nullptr);
    scheduleDispatch();
}

WireConnection::~WireConnection()
{
    dbus_connection_remove_filter(m_connection, Integration::filter, this);
    dbus_connection_set_dispatch_status_function(m_connection, nullptr, nullptr, nullptr);
    dbus_connection_set_watch_functions(m_connection, nullptr, nullptr, nullptr, nullptr, nullptr);
    dbus_connection_set_timeout_functions(m_connection, nullptr, nullptr, nullptr, nullptr, nullptr);
    dbus_connection_close(m_connection);
    dbus_connection_unref(m_connection);
}

bool WireConnection::isConnected() const
{
    return !m_disconnected && dbus_connection_get_is_connected(m_connection);
}

bool WireConnection::isAuthenticated() const
{
    return dbus_connection_get_is_authenticated(m_connection);
}

bool WireConnection::canPassUnixFds() const
{
    return dbus_connection_can_send_type(m_connection, DBUS_TYPE_UNIX_FD);
}

int WireConnection::socketFd() const
{
    int fd = -1;
    if (!dbus_connection_get_socket(m_connection, &fd))
        return -1;
    return fd;
}

qint64 WireConnection::outgoingBytes() const
{
    return dbus_connection_get_outgoing_size(m_connection);
}

quint32 WireConnection::send(MessagePtr message)
{
    if (!message || !isConnected())
        return 0;
    dbus_uint32_t serial = 0;
    if (!dbus_connection_send(m_connection, message.get(), &serial))
        return 0;
    return serial;
}

void WireConnection::close()
{
    if (m_disconnected)
        return;
    dbus_connection_close(m_connection);
    QPointer<WireConnection> self(this);
    QTimer::singleShot(0, this, [self]() {
        if (self)
            self->noteDisconnected();
    });
}

void WireConnection::scheduleDispatch()
{
    if (m_dispatchScheduled)
        return;
    m_dispatchScheduled = true;
    QPointer<WireConnection> self(this);
    QTimer::singleShot(0, this, [self]() {
        if (self)
            self->dispatch();
    });
}

void WireConnection::dispatch()
{
    m_dispatchScheduled = false;
    // Bounded per pass so a flooding peer cannot starve the event loop.
    constexpr int MaxMessagesPerPass = 64;
    for (int i = 0; i < MaxMessagesPerPass; ++i) {
        if (dbus_connection_dispatch(m_connection) != DBUS_DISPATCH_DATA_REMAINS)
            return;
    }
    scheduleDispatch();
}

void WireConnection::handle(DBusMessage *message)
{
    if (isLocalDisconnected(message)) {
        noteDisconnected();
        return;
    }
    if (m_handler && !m_disconnected)
        m_handler(message);
}

void WireConnection::noteDisconnected()
{
    if (m_disconnected)
        return;
    m_disconnected = true;
    emit disconnected();
}

// ------------------------------------------------------------------ server

struct WireServer::Integration {
    WireServer *owner;
    void afterWatch() const { Q_UNUSED(owner) }

    static void newConnection(DBusServer *, DBusConnection *connection, void *data)
    {
        auto *server = static_cast<WireServer *>(data);
        dbus_connection_set_unix_user_function(connection, allowOwnUidOnly, nullptr, nullptr);
        dbus_connection_set_allow_anonymous(connection, FALSE);
        dbus_connection_set_max_message_size(connection, MaxInboundMessageBytes);
        dbus_connection_set_max_received_size(connection, MaxInboundQueuedBytes);
        dbus_connection_set_max_message_unix_fds(connection, MaxInboundMessageFds);
        dbus_connection_set_max_received_unix_fds(connection, MaxInboundQueuedFds);
        auto *wire = new WireConnection(connection);
        emit server->newConnection(wire);
    }
};

namespace {
using ServerLoop = LoopCallbacks<WireServer::Integration>;
}

WireServer::WireServer(QObject *parent)
    : QObject(parent)
{
}

WireServer::~WireServer()
{
    stop();
}

Result WireServer::listen(const QString &address)
{
    stop();
    DBusError error;
    dbus_error_init(&error);
    DBusServer *server = dbus_server_listen(address.toUtf8().constData(), &error);
    if (!server) {
        const Result r(Error::NetworkUnreachable,
                       QStringLiteral("Cannot listen on %1: %2").arg(address, QString::fromUtf8(error.message)));
        dbus_error_free(&error);
        return r;
    }
    std::array<const char *, 2> mechanisms = { { "EXTERNAL", nullptr } };
    dbus_server_set_auth_mechanisms(server, mechanisms.data());
    auto *integration = new Integration{ this };
    dbus_server_set_watch_functions(server, ServerLoop::addWatch, ServerLoop::removeWatch, ServerLoop::toggleWatch,
                                    integration, [](void *data) { delete static_cast<Integration *>(data); });
    dbus_server_set_timeout_functions(server, ServerLoop::addTimeout, ServerLoop::removeTimeout,
                                      ServerLoop::toggleTimeout, nullptr, nullptr);
    dbus_server_set_new_connection_function(server, Integration::newConnection, this, nullptr);
    m_server = server;
    return Result::success();
}

QString WireServer::address() const
{
    if (!m_server)
        return QString();
    char *address = dbus_server_get_address(m_server);
    const QString result = QString::fromUtf8(address);
    dbus_free(address);
    return result;
}

void WireServer::stop()
{
    if (!m_server)
        return;
    dbus_server_set_new_connection_function(m_server, nullptr, nullptr, nullptr);
    dbus_server_set_watch_functions(m_server, nullptr, nullptr, nullptr, nullptr, nullptr);
    dbus_server_set_timeout_functions(m_server, nullptr, nullptr, nullptr, nullptr, nullptr);
    dbus_server_disconnect(m_server);
    dbus_server_unref(m_server);
    m_server = nullptr;
}

} // namespace Bridge
} // namespace NetVfs
