# SPDX-License-Identifier: LGPL-2.1-or-later
# The SFTP plugin of the build tree over the library it ships with
# (libnetvfs-rs.so, rust/netvfs-sftp): the SSH key tools on its root object
# against keys of the host's ssh-keygen and openssl, and connection failures
# that need no server. The protocol itself is tested in Rust and against
# the interop containers.
include(../../test.pri)
TARGET = tst_sftp
DEFINES += NETVFS_TEST_RS_RELEASE_LIB=\\\"$$NETVFS_LIB_OUT/netvfs/libnetvfs-rs.so\\\"
SOURCES = tst_sftp.cpp
QT += network
