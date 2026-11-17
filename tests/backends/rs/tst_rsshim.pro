# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_rsshim: the shim (compiled in too, to reach createBackend() and the key tools) and libnetvfs-mem.so against libnetvfs-rs.so with the mem backend.
include(../../test.pri)
include(rstest.pri)
include($$NETVFS_ROOT/src/backends/rs/rs.pri)
TARGET = tst_rsshim
DEFINES += NETVFS_TEST_RS_LIB=\\\"$$NETVFS_TEST_RS_LIB\\\"
DEFINES += NETVFS_TEST_CORE_LIB=\\\"$$NETVFS_LIB_OUT/libnetvfs.so.1\\\"
SOURCES += tst_rsshim.cpp
