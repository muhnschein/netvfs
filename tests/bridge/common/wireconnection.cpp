// SPDX-License-Identifier: LGPL-2.1-or-later
#include "wireconnection.h"

#include "dbusloop.h"

#include <QtCore/QPointer>
#include <QtCore/QSocketNotifier>
#include <QtCore/QTimer>

#include <dbus/dbus.h>

#include <memory>

// What libdbus calls back into: the connection (dispatches its queue, handles
// its messages). The libdbus callbacks are in dbusloop.c.
struct NetVfsLoopOwner {
    NetVfsLoopOwner() = default;
    NetVfsLoopOwner(const NetVfsLoopOwner &) = delete;
    NetVfsLoopOwner &operator=(const NetVfsLoopOwner &) = delete;
    virtual ~NetVfsLoopOwner() = default;

    // After every watch activation (the connection schedules a dispatch).
    virtual void afterWatch() = 0;
    virtual DBusHandlerResult message(DBusMessage *message) = 0;
    virtual void dispatchStatus(DBusDispatchStatus status) = 0;
};

namespace NetVfs::BridgeTest {

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
    dbus_connection_unref(connection);
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

} // namespace NetVfs::BridgeTest


dbus_bool_t netvfs_loop_watch_added(DBusWatch *watch, NetVfsLoopOwner *owner)
{
    // Owned through the watch data until the watch is removed.
    auto notifier = std::make_unique<NetVfs::BridgeTest::WatchNotifier>(watch, owner);
    dbus_watch_set_data(watch, notifier.release(), nullptr);
    return TRUE;
}

void netvfs_loop_watch_removed(DBusWatch *watch)
{
    if (auto *notifier = static_cast<NetVfs::BridgeTest::WatchNotifier *>(dbus_watch_get_data(watch)))
        notifier->detach();
    dbus_watch_set_data(watch, nullptr, nullptr);
}

void netvfs_loop_watch_toggled(DBusWatch *watch)
{
    if (auto *notifier = static_cast<NetVfs::BridgeTest::WatchNotifier *>(dbus_watch_get_data(watch)))
        notifier->toggle();
}

dbus_bool_t netvfs_loop_timeout_added(DBusTimeout *timeout)
{
    auto timer = std::make_unique<NetVfs::BridgeTest::TimeoutTimer>(timeout);
    dbus_timeout_set_data(timeout, timer.release(), nullptr);
    return TRUE;
}

void netvfs_loop_timeout_removed(DBusTimeout *timeout)
{
    if (auto *timer = static_cast<NetVfs::BridgeTest::TimeoutTimer *>(dbus_timeout_get_data(timeout)))
        timer->detach();
    dbus_timeout_set_data(timeout, nullptr, nullptr);
}

void netvfs_loop_timeout_toggled(DBusTimeout *timeout)
{
    if (auto *timer = static_cast<NetVfs::BridgeTest::TimeoutTimer *>(dbus_timeout_get_data(timeout)))
        timer->toggle();
}

DBusHandlerResult netvfs_loop_message(NetVfsLoopOwner *owner, DBusConnection *, DBusMessage *message)
{
    return owner->message(message);
}

void netvfs_loop_dispatch_status(NetVfsLoopOwner *owner, DBusConnection *, DBusDispatchStatus status)
{
    owner->dispatchStatus(status);
}
