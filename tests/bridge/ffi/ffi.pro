# SPDX-License-Identifier: LGPL-2.1-or-later
# C ABI of libnetvfs-bridge-ffi.so, loaded as the Rust bridge loads it, with the fake backend's control table (../ffifake).
include(../../test.pri)
TARGET = tst_bridgeffi
INCLUDEPATH += $$NETVFS_ROOT/src/bridge/ffi $$PWD/../ffifake
LIBS += -ldl
DEFINES += NETVFS_TEST_FFI_LIB=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-bridge-ffi.so\\\"
DEFINES += NETVFS_TEST_FFI_FAKE_LIB=\\\"$$NETVFS_LIB_OUT/libnetvfs-bridge-ffi-fake.so\\\"
# The library exports only nvb_ffi_get, so the test compiles marshal.cpp itself for marshal.h's templates (cases no backend produces).
SOURCES += tst_bridgeffi.cpp $$NETVFS_ROOT/src/bridge/ffi/marshal.cpp
