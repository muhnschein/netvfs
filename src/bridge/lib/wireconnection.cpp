// SPDX-License-Identifier: LGPL-2.1-or-later
#include "wireconnection.h"

#include "dbusloop.h"

#include <QtCore/QPointer>
#include <QtCore/QSocketNotifier>
#include <QtCore/QTimer>

#include <dbus/dbus.h>

#include <array>
#include <memory>

namespace NetVfs::Bridge {

namespace {

// XB-17 sizes: no inbound call needs more than a few KiB (the largest is
// ConnectAdHoc); Upload and Download carry exactly one fd.
constexpr long MaxInboundMessageBytes = 1 << 20;
constexpr long MaxInboundQueuedBytes = 8 << 20;
constexpr long MaxInboundMessageFds = 2;
constexpr long MaxInboundQueuedFds = 8;

} // namespace
} // namespace NetVfs::Bridge

// What libdbus calls back into: a connection (dispatches its queue, handles
// its messages) or a server (accepts connections). The libdbus callbacks are
// in dbusloop.c.
struct NetVfsLoopOwner {
    NetVfsLoopOwner() = default;
    NetVfsLoopOwner(const NetVfsLoopOwner &) = delete;
    NetVfsLoopOwner &operator=(const NetVfsLoopOwner &) = delete;
    virtual ~NetVfsLoopOwner() = default;

    // After every watch activation (a connection schedules a dispatch).
    virtual void afterWatch() = 0;
    // Connections only: a message arrived.
    virtual DBusHandlerResult message(DBusMessage *message) = 0;
    // Connections only: the dispatch queue changed.
    virtual void dispatchStatus(DBusDispatchStatus status) = 0;
    // Servers only: a client connected.
    virtual void accepted(DBusConnection *connection) = 0;
};

namespace NetVfs::Bridge {

namespace {

// Read and write notifiers of one DBusWatch. Owned through the watch data;
// deleted later because removal may happen inside its own activation.
class WatchNotifier : public QObject
{
public:
    WatchNotifier(DBusWatch *watch, NetVfsLoopOwner *owner)
        : m_watch(watch), m_owner(owner)
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
        m_owner->afterWatch();
    }

    DBusWatch *m_watch;
    NetVfsLoopOwner *m_owner;
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

bool isLocalDisconnected(DBusMessage *message)
{
    return dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected");
}

} // namespace

// -------------------------------------------------------------- connection

struct WireConnection::Integration final : NetVfsLoopOwner {
    explicit Integration(WireConnection *connection) : owner(connection) {}

    void afterWatch() override { owner->scheduleDispatch(); }
    DBusHandlerResult message(DBusMessage *received) override
    {
        owner->handle(received);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    void dispatchStatus(DBusDispatchStatus status) override
    {
        if (status == DBUS_DISPATCH_DATA_REMAINS)
            owner->scheduleDispatch();
    }
    void accepted(DBusConnection *) override
    {
        // a connection does not accept clients
    }

    WireConnection *owner;
};

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
    , m_integration(std::make_unique<Integration>(this))
{
    NetVfsLoopOwner *owner = m_integration.get();
    dbus_connection_set_exit_on_disconnect(m_connection, FALSE);
    dbus_connection_set_watch_functions(m_connection, netvfs_loop_add_watch, netvfs_loop_remove_watch,
                                        netvfs_loop_toggle_watch, owner, nullptr);
    dbus_connection_set_timeout_functions(m_connection, netvfs_loop_add_timeout, netvfs_loop_remove_timeout,
                                          netvfs_loop_toggle_timeout, nullptr, nullptr);
    dbus_connection_set_dispatch_status_function(m_connection, netvfs_loop_status, owner, nullptr);
    dbus_connection_add_filter(m_connection, netvfs_loop_filter, owner, nullptr);
    scheduleDispatch();
}

WireConnection::~WireConnection()
{
    NetVfsLoopOwner *owner = m_integration.get();
    dbus_connection_remove_filter(m_connection, netvfs_loop_filter, owner);
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

struct WireServer::Integration final : NetVfsLoopOwner {
    explicit Integration(WireServer *server) : owner(server) {}

    void afterWatch() override
    {
        // a server has no dispatch queue
    }
    DBusHandlerResult message(DBusMessage *) override { return DBUS_HANDLER_RESULT_NOT_YET_HANDLED; }
    void dispatchStatus(DBusDispatchStatus) override
    {
        // a server has no dispatch queue
    }
    void accepted(DBusConnection *connection) override
    {
        dbus_connection_set_unix_user_function(connection, netvfs_loop_own_uid_only, nullptr, nullptr);
        dbus_connection_set_allow_anonymous(connection, FALSE);
        dbus_connection_set_max_message_size(connection, MaxInboundMessageBytes);
        dbus_connection_set_max_received_size(connection, MaxInboundQueuedBytes);
        dbus_connection_set_max_message_unix_fds(connection, MaxInboundMessageFds);
        dbus_connection_set_max_received_unix_fds(connection, MaxInboundQueuedFds);
        auto wire = std::make_unique<WireConnection>(connection);
        emit owner->newConnection(wire.release());   // the receiver owns it
    }

    WireServer *owner;
};

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
    m_integration = std::make_unique<Integration>(this);
    NetVfsLoopOwner *owner = m_integration.get();
    dbus_server_set_watch_functions(server, netvfs_loop_add_watch, netvfs_loop_remove_watch, netvfs_loop_toggle_watch,
                                    owner, nullptr);
    dbus_server_set_timeout_functions(server, netvfs_loop_add_timeout, netvfs_loop_remove_timeout,
                                      netvfs_loop_toggle_timeout, nullptr, nullptr);
    dbus_server_set_new_connection_function(server, netvfs_loop_new, owner, nullptr);
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

} // namespace NetVfs::Bridge

// The typed side of the libdbus callbacks (dbusloop.c).

dbus_bool_t netvfs_loop_watch_added(DBusWatch *watch, NetVfsLoopOwner *owner)
{
    // Owned through the watch data until the watch is removed.
    auto notifier = std::make_unique<NetVfs::Bridge::WatchNotifier>(watch, owner);
    dbus_watch_set_data(watch, notifier.release(), nullptr);
    return TRUE;
}

void netvfs_loop_watch_removed(DBusWatch *watch)
{
    if (auto *notifier = static_cast<NetVfs::Bridge::WatchNotifier *>(dbus_watch_get_data(watch)))
        notifier->detach();
    dbus_watch_set_data(watch, nullptr, nullptr);
}

void netvfs_loop_watch_toggled(DBusWatch *watch)
{
    if (auto *notifier = static_cast<NetVfs::Bridge::WatchNotifier *>(dbus_watch_get_data(watch)))
        notifier->toggle();
}

dbus_bool_t netvfs_loop_timeout_added(DBusTimeout *timeout)
{
    auto timer = std::make_unique<NetVfs::Bridge::TimeoutTimer>(timeout);
    dbus_timeout_set_data(timeout, timer.release(), nullptr);
    return TRUE;
}

void netvfs_loop_timeout_removed(DBusTimeout *timeout)
{
    if (auto *timer = static_cast<NetVfs::Bridge::TimeoutTimer *>(dbus_timeout_get_data(timeout)))
        timer->detach();
    dbus_timeout_set_data(timeout, nullptr, nullptr);
}

void netvfs_loop_timeout_toggled(DBusTimeout *timeout)
{
    if (auto *timer = static_cast<NetVfs::Bridge::TimeoutTimer *>(dbus_timeout_get_data(timeout)))
        timer->toggle();
}

DBusHandlerResult netvfs_loop_message(NetVfsLoopOwner *owner, DBusMessage *message)
{
    return owner->message(message);
}

void netvfs_loop_dispatch_status(NetVfsLoopOwner *owner, DBusDispatchStatus status)
{
    owner->dispatchStatus(status);
}

void netvfs_loop_new_connection(NetVfsLoopOwner *owner, DBusConnection *connection)
{
    owner->accepted(connection);
}
