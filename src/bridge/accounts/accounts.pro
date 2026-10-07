# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-accounts (SPEC-v2 XB-2a): the setgid `privileged` reader of the
# accounts database, so that netvfs-bridge runs without the group.
include(../../../common.pri)

TEMPLATE = app
TARGET = netvfs-accounts
DESTDIR = $$NETVFS_BUILD/libexec/netvfs
QT = core dbus network
CONFIG += console link_pkgconfig
CONFIG -= app_bundle
PKGCONFIG += dbus-1 accounts-qt5 libsignon-qt5
INCLUDEPATH += $$PWD/../lib
LIBS += -L$$NETVFS_LIB_OUT -lnetvfsbridge $$netvfsCoreLibs()
PRE_TARGETDEPS += $$NETVFS_LIB_OUT/libnetvfsbridge.a
# Tests run the helper from the build tree; the installed helper finds
# libnetvfs through the system library path (no RUNPATH in packages, which a
# set-id program would ignore anyway).
!equals(NETVFS_BUILD_TESTS, 0): QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

SOURCES = main.cpp

target.path = /usr/libexec/netvfs
INSTALLS += target
