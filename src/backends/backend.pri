# SPDX-License-Identifier: LGPL-2.1-or-later
# Common settings for a backend plugin libnetvfs-<NETVFS_PROVIDER>.so that
# statically contains its protocol library (SPEC 4.1, SEC-7).
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfs-$$NETVFS_PROVIDER
DESTDIR = $$NETVFS_BACKEND_OUT
QT = core
CONFIG += plugin hide_symbols
LIBS += $$netvfsCoreLibs()
QMAKE_LFLAGS += -Wl,--exclude-libs,ALL -Wl,--no-undefined
INCLUDEPATH += $$VENDOR_PREFIX/include

target.path = $$NETVFS_BACKEND_INSTALL_DIR
INSTALLS += target
