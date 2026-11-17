# SPDX-License-Identifier: LGPL-2.1-or-later
# Plain C, libc only: generators run early.
include(../../../common.pri)

TEMPLATE = app
TARGET = netvfs-bridge-generator
DESTDIR = $$NETVFS_BUILD/bin
CONFIG += console
CONFIG -= qt app_bundle
QMAKE_CFLAGS += -std=c11 -D_DEFAULT_SOURCE
equals(NETVFS_WERROR, 1): QMAKE_CFLAGS += -Werror
SOURCES = netvfs-bridge-generator.c

target.path = /usr/lib/systemd/user-generators
INSTALLS += target
