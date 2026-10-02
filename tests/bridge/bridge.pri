# SPDX-License-Identifier: LGPL-2.1-or-later
# A netvfs-bridge test (SPEC-v2 XT-7): links the bridge library, the fake
# backend helpers and libdbus; the bridge runs in-process.
include(../test.pri)
QT += dbus network
CONFIG += link_pkgconfig
PKGCONFIG += dbus-1 accounts-qt5 libsignon-qt5
INCLUDEPATH += $$NETVFS_ROOT/src/bridge/lib $$PWD/common
LIBS = -L$$NETVFS_LIB_OUT -lnetvfsbridge $$LIBS
PRE_TARGETDEPS += $$NETVFS_LIB_OUT/libnetvfsbridge.a
DEFINES += NETVFS_TEST_BIN_DIR=\\\"$$NETVFS_BUILD/bin\\\"
HEADERS += $$PWD/common/bridgetest.h
SOURCES += $$PWD/common/bridgetest.cpp
