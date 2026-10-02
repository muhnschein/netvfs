/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef NETVFS_BRIDGE_DBUSLOOP_H
#define NETVFS_BRIDGE_DBUSLOOP_H

/*
 * Glue between libdbus and the Qt event loop. libdbus dictates the signatures
 * of its callbacks (untyped `void *` user data), so they live in C
 * (dbusloop.c); they only turn the user data into the typed NetVfsLoopOwner
 * and call the functions below, which wireconnection.cpp implements.
 */
#include <dbus/dbus.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The WireConnection or WireServer whose libdbus object is being driven. */
struct NetVfsLoopOwner;

/* Implemented in C++ (wireconnection.cpp). */
dbus_bool_t netvfs_loop_watch_added(DBusWatch *watch, struct NetVfsLoopOwner *owner);
void netvfs_loop_watch_removed(DBusWatch *watch);
void netvfs_loop_watch_toggled(DBusWatch *watch);
dbus_bool_t netvfs_loop_timeout_added(DBusTimeout *timeout);
void netvfs_loop_timeout_removed(DBusTimeout *timeout);
void netvfs_loop_timeout_toggled(DBusTimeout *timeout);
DBusHandlerResult netvfs_loop_message(struct NetVfsLoopOwner *owner, DBusMessage *message);
void netvfs_loop_dispatch_status(struct NetVfsLoopOwner *owner, DBusDispatchStatus status);
void netvfs_loop_new_connection(struct NetVfsLoopOwner *owner, DBusConnection *connection);

/* The callbacks for libdbus (dbusloop.c). Their user data is the NetVfsLoopOwner. */
extern const DBusAddWatchFunction netvfs_loop_add_watch;
extern const DBusRemoveWatchFunction netvfs_loop_remove_watch;
extern const DBusWatchToggledFunction netvfs_loop_toggle_watch;
extern const DBusAddTimeoutFunction netvfs_loop_add_timeout;
extern const DBusRemoveTimeoutFunction netvfs_loop_remove_timeout;
extern const DBusTimeoutToggledFunction netvfs_loop_toggle_timeout;
extern const DBusHandleMessageFunction netvfs_loop_filter;
extern const DBusDispatchStatusFunction netvfs_loop_status;
extern const DBusNewConnectionFunction netvfs_loop_new;
/* XB-5 first line: only the bridge's own uid authenticates (libdbus would
 * otherwise also accept root). */
extern const DBusAllowUnixUserFunction netvfs_loop_own_uid_only;

#ifdef __cplusplus
}
#endif

#endif
