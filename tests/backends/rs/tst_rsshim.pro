# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_rsshim: the shim (src/backends/rs, compiled in here as well, so that
# the test reaches createBackend() and the key tools directly) and the test
# plugin libnetvfs-mem.so against libnetvfs-rs.so with the mem backend.
include(../../test.pri)
include(rstest.pri)
include($$NETVFS_ROOT/src/backends/rs/rs.pri)
TARGET = tst_rsshim
DEFINES += NETVFS_TEST_RS_LIB=\\\"$$NETVFS_TEST_RS_LIB\\\"
DEFINES += NETVFS_TEST_CORE_LIB=\\\"$$NETVFS_LIB_OUT/libnetvfs.so.1\\\"
SOURCES += tst_rsshim.cpp
