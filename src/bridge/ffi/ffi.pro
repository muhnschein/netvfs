# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../common.pri)

TEMPLATE = lib
TARGET = netvfs-bridge-ffi
DESTDIR = $$NETVFS_LIB_OUT/netvfs
QT = core network
CONFIG += plugin hide_symbols
QMAKE_LFLAGS += -Wl,--version-script=$$PWD/exports.map
QMAKE_LFLAGS += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LIBS += $$netvfsCoreLibs()
!equals(NETVFS_BUILD_TESTS, 0): QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

HEADERS = \
    ffi_p.h \
    marshal.h \
    netvfs_bridge_ffi.h

SOURCES = \
    conn.cpp \
    discovery.cpp \
    establish.cpp \
    ffi.cpp \
    io.cpp \
    marshal.cpp \
    ops.cpp

OTHER_FILES += exports.map

target.path = $$[QT_INSTALL_LIBS]/netvfs
INSTALLS += target
