# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../common.pri)

TEMPLATE = app
TARGET = netvfs-cli
DESTDIR = $$NETVFS_BUILD/bin
QT = core
CONFIG += console
CONFIG -= app_bundle
LIBS += $$netvfsCoreLibs()
# Tests run the tool from the build tree; the installed tool finds libnetvfs
# through the system library path (no RUNPATH in packages).
!equals(NETVFS_BUILD_TESTS, 0): QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

include(cli.pri)
SOURCES += main.cpp

# SPEC-v2 XP-1: package netvfs-cli
target.path = /usr/bin
INSTALLS += target
