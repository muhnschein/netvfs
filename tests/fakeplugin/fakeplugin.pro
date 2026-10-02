# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-fake.so: a backend plugin over the in-memory FakeServer, for tests.
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfs-fake
DESTDIR = $$NETVFS_LIB_OUT/netvfs/test-backends
QT = core
CONFIG += plugin
INCLUDEPATH += $$NETVFS_ROOT/tests/common
LIBS += -L$$NETVFS_LIB_OUT -lnetvfstest $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
target.path =
SOURCES = fakeplugin.cpp
