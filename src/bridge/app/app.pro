# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../common.pri)

TEMPLATE = app
TARGET = netvfs-bridge
DESTDIR = $$NETVFS_BUILD/bin
QT = core dbus network
CONFIG += console link_pkgconfig
CONFIG -= app_bundle
PKGCONFIG += dbus-1 accounts-qt5 libsignon-qt5
INCLUDEPATH += $$PWD/../lib
LIBS += -L$$NETVFS_LIB_OUT -lnetvfsbridge $$netvfsCoreLibs()
PRE_TARGETDEPS += $$NETVFS_LIB_OUT/libnetvfsbridge.a
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

SOURCES = main.cpp

# XB-2
target.path = /usr/libexec/netvfs
INSTALLS += target
