/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_TEST_DBUSLOOP_H
#define NETVFS_TEST_DBUSLOOP_H

#include <dbus/dbus.h>

#ifdef __cplusplus
extern "C" {
#endif

struct NetVfsLoopOwner;

dbus_bool_t netvfs_loop_watch_added(DBusWatch *watch, struct NetVfsLoopOwner *owner);
void netvfs_loop_watch_removed(DBusWatch *watch);
void netvfs_loop_watch_toggled(DBusWatch *watch);
dbus_bool_t netvfs_loop_timeout_added(DBusTimeout *timeout);
void netvfs_loop_timeout_removed(DBusTimeout *timeout);
void netvfs_loop_timeout_toggled(DBusTimeout *timeout);
DBusHandlerResult netvfs_loop_message(struct NetVfsLoopOwner *owner, DBusConnection *connection, DBusMessage *message);
void netvfs_loop_dispatch_status(struct NetVfsLoopOwner *owner, DBusConnection *connection,
                                 DBusDispatchStatus status);

extern const DBusAddWatchFunction netvfs_loop_add_watch;
extern const DBusRemoveWatchFunction netvfs_loop_remove_watch;
extern const DBusWatchToggledFunction netvfs_loop_toggle_watch;
extern const DBusAddTimeoutFunction netvfs_loop_add_timeout;
extern const DBusRemoveTimeoutFunction netvfs_loop_remove_timeout;
extern const DBusTimeoutToggledFunction netvfs_loop_toggle_timeout;
extern const DBusHandleMessageFunction netvfs_loop_filter;
extern const DBusDispatchStatusFunction netvfs_loop_status;

#ifdef __cplusplus
}
#endif

#endif
