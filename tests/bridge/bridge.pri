# SPDX-License-Identifier: LGPL-2.1-or-later
# A black-box test of the netvfs-bridge binary (SPEC-v2 XT-7; design §4.3):
# the Rust bridge as its own process, with the C ABI and the fake backend of
# the build tree, and the libdbus client of common/ talking to it. The client
# is independent of the bridge's zbus, so these tests show that the two
# interoperate.
include(../test.pri)
CONFIG += link_pkgconfig
PKGCONFIG += dbus-1
INCLUDEPATH += $$PWD/common
DEFINES += NETVFS_TEST_LIBEXEC_DIR=\\\"$$NETVFS_BUILD/libexec/netvfs\\\"
DEFINES += NETVFS_TEST_BRIDGE_FFI=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-bridge-ffi.so\\\"
# Under the sanitizers libnetvfs-bridge-ffi.so is instrumented and the Rust
# bridge is not: the bridge must load gcc's runtimes first (the Makefile does
# the same for the Rust tests, check-rust-ffi).
equals(NETVFS_SANITIZE, 1) {
    NETVFS_SANITIZER_PRELOAD = $$system($$QMAKE_CXX -print-file-name=libasan.so):$$system($$QMAKE_CXX -print-file-name=libubsan.so)
    DEFINES += NETVFS_TEST_BRIDGE_PRELOAD=\\\"$$NETVFS_SANITIZER_PRELOAD\\\"
}
HEADERS += \
    $$PWD/common/bridgetest.h \
    $$PWD/common/dbusloop.h \
    $$PWD/common/unixfd.h \
    $$PWD/common/wire.h \
    $$PWD/common/wireconnection.h
SOURCES += \
    $$PWD/common/bridgetest.cpp \
    $$PWD/common/dbusloop.c \
    $$PWD/common/unixfd.cpp \
    $$PWD/common/wire.cpp \
    $$PWD/common/wireconnection.cpp
