# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-buteo.a: the shared BackupClient and the backup operations
# (SPEC 8.1), linked into each of the Buteo plugins.
include(../buteo.pri)

TEMPLATE = lib
TARGET = netvfs-buteo
DESTDIR = $$NETVFS_LIB_OUT
QT = core dbus
CONFIG += staticlib hide_symbols

HEADERS = \
    backupclient.h \
    backuprun.h \
    backupservice.h \
    backupsteps.h \
    networkjob.h \
    replyhandler.h

SOURCES = \
    backupclient.cpp \
    backuprun.cpp \
    backupservice.cpp \
    backupsteps.cpp \
    networkjob.cpp
