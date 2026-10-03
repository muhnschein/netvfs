/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "dbusloop.h"

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
    return netvfs_loop_watch_added(watch, (struct NetVfsLoopOwner *)data);
}

static void remove_watch(DBusWatch *watch, void *data)
{
    (void)data;
    netvfs_loop_watch_removed(watch);
}

static void toggle_watch(DBusWatch *watch, void *data)
{
    (void)data;
    netvfs_loop_watch_toggled(watch);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{
    (void)data;
    return netvfs_loop_timeout_added(timeout);
}

static void remove_timeout(DBusTimeout *timeout, void *data)
{
    (void)data;
    netvfs_loop_timeout_removed(timeout);
}

static void toggle_timeout(DBusTimeout *timeout, void *data)
{
    (void)data;
    netvfs_loop_timeout_toggled(timeout);
}

static DBusHandlerResult filter(DBusConnection *connection, DBusMessage *message, void *data)
{
    return netvfs_loop_message((struct NetVfsLoopOwner *)data, connection, message);
}

static void dispatch_status(DBusConnection *connection, DBusDispatchStatus status, void *data)
{
    netvfs_loop_dispatch_status((struct NetVfsLoopOwner *)data, connection, status);
}

static void new_connection(DBusServer *server, DBusConnection *connection, void *data)
{
    netvfs_loop_new_connection((struct NetVfsLoopOwner *)data, server, connection);
}

static dbus_bool_t own_uid_only(DBusConnection *connection, unsigned long uid, void *data)
{
    (void)data;
    return netvfs_loop_uid_allowed(connection, uid);
}

const DBusAddWatchFunction netvfs_loop_add_watch = add_watch;
const DBusRemoveWatchFunction netvfs_loop_remove_watch = remove_watch;
const DBusWatchToggledFunction netvfs_loop_toggle_watch = toggle_watch;
const DBusAddTimeoutFunction netvfs_loop_add_timeout = add_timeout;
const DBusRemoveTimeoutFunction netvfs_loop_remove_timeout = remove_timeout;
const DBusTimeoutToggledFunction netvfs_loop_toggle_timeout = toggle_timeout;
const DBusHandleMessageFunction netvfs_loop_filter = filter;
const DBusDispatchStatusFunction netvfs_loop_status = dispatch_status;
const DBusNewConnectionFunction netvfs_loop_new = new_connection;
const DBusAllowUnixUserFunction netvfs_loop_own_uid_only = own_uid_only;
