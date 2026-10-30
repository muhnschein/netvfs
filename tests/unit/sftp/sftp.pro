# SPDX-License-Identifier: LGPL-2.1-or-later
# SFTP plugin of the build tree over its shipped library (libnetvfs-rs.so): SSH key tools on its root object against keys of the host's ssh-keygen and openssl, and connection failures needing no server. The protocol is tested in Rust and against the interop containers.
include(../../test.pri)
TARGET = tst_sftp
DEFINES += NETVFS_TEST_RS_RELEASE_LIB=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-rs.so\\\"
# Key files of the Rust tests (rust/netvfs-sftp/testdata/keys).
DEFINES += NETVFS_TEST_KEY_FIXTURES=\\\"$$PWD/../../../rust/netvfs-sftp/testdata/keys\\\"
SOURCES = tst_sftp.cpp
QT += network
