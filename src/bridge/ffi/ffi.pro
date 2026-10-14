# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-bridge-ffi.so: the C ABI between the Rust netvfs-bridge and the
# C++ backends (netvfs_bridge_ffi.h; design: phase2-design.md §1). Loaded with
# dlopen, so no soname versioning; it exports only nvb_ffi_get.
include(../../../common.pri)

TEMPLATE = lib
TARGET = netvfs-bridge-ffi
DESTDIR = $$NETVFS_LIB_OUT/netvfs
QT = core network
CONFIG += plugin hide_symbols
QMAKE_LFLAGS += -Wl,--version-script=$$PWD/exports.map
LIBS += $$netvfsCoreLibs()
# Tests load it from the build tree; the installed one finds libnetvfs
# through the system library path (no RUNPATH in packages).
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

# Next to the backend folder (BackendLoader: <libdir>/netvfs/backends).
target.path = $$[QT_INSTALL_LIBS]/netvfs
INSTALLS += target
