# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
include(rstest.pri)
include($$NETVFS_ROOT/src/backends/rs/rs.pri)
TARGET = tst_rsshim
DEFINES += NETVFS_TEST_RS_LIB=\\\"$$NETVFS_TEST_RS_LIB\\\"
DEFINES += NETVFS_TEST_CORE_LIB=\\\"$$NETVFS_LIB_OUT/libnetvfs.so.1\\\"
SOURCES += tst_rsshim.cpp
