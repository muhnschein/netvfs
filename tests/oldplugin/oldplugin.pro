# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-oldiid.so: a backend plugin that declares the API v1 interface
# ID, for the loader's IID check (SPEC-v2 XC-1).
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfs-oldiid
DESTDIR = $$NETVFS_LIB_OUT/netvfs/test-backends
QT = core
CONFIG += plugin
INCLUDEPATH += $$NETVFS_ROOT/tests/common
LIBS += -L$$NETVFS_LIB_OUT -lnetvfstest $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
target.path =
SOURCES = oldplugin.cpp
