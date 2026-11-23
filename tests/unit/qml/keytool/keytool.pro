# SPDX-License-Identifier: LGPL-2.1-or-later
include(../qmltest.pri)
TARGET = tst_qmlkeytool
DEFINES += NETVFS_TEST_RS_RELEASE_LIB=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-rs.so\\\"
SOURCES += tst_qmlkeytool.cpp
