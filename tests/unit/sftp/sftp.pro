# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
TARGET = tst_sftp
DEFINES += NETVFS_TEST_RS_RELEASE_LIB=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-rs.so\\\"
DEFINES += NETVFS_TEST_KEY_FIXTURES=\\\"$$PWD/../../../rust/netvfs-sftp/testdata/keys\\\"
SOURCES = tst_sftp.cpp
QT += network
