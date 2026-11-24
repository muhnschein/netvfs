# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../../common.pri)
include($$NETVFS_ROOT/src/backends/rs/rs.pri)

TEMPLATE = lib
TARGET = netvfs-mem
DESTDIR = $$NETVFS_LIB_OUT/netvfs/test-backends
QT = core
CONFIG += plugin hide_symbols
LIBS += $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
target.path =
SOURCES += memplugin.cpp
