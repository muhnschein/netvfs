# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../common.pri)

TEMPLATE = lib
TARGET = netvfs-bridge-ffi-fake
DESTDIR = $$NETVFS_LIB_OUT
QT = core
CONFIG += plugin hide_symbols
INCLUDEPATH += $$NETVFS_ROOT/tests/common $$NETVFS_ROOT/src/bridge/ffi
QMAKE_LFLAGS += -Wl,--version-script=$$PWD/exports.map
LIBS += -L$$NETVFS_LIB_OUT -lnetvfstest $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
HEADERS = nvb_fake.h
SOURCES = ffifake.cpp
OTHER_FILES += exports.map
target.path =
