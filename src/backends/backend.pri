# SPDX-License-Identifier: LGPL-2.1-or-later
# Backend plugin libnetvfs-<NETVFS_PROVIDER>.so.
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfs-$$NETVFS_PROVIDER
DESTDIR = $$NETVFS_BACKEND_OUT
QT = core
CONFIG += plugin hide_symbols
LIBS += $$netvfsCoreLibs()
QMAKE_LFLAGS += -Wl,--exclude-libs,ALL -Wl,--no-undefined

target.path = $$NETVFS_BACKEND_INSTALL_DIR
INSTALLS += target
