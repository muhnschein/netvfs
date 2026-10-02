# SPDX-License-Identifier: LGPL-2.1-or-later
# SFTP backend logic that needs no server: mapping and policy helpers
# (compiled in), the SSH key tools and connection failures (through the
# plugin in the build tree).
include(../../test.pri)
TARGET = tst_sftp
INCLUDEPATH += $$NETVFS_ROOT/src/backends/sftp $$VENDOR_PREFIX/include
HEADERS = $$NETVFS_ROOT/src/backends/sftp/sftpsupport.h
SOURCES = tst_sftp.cpp $$NETVFS_ROOT/src/backends/sftp/sftpsupport.cpp
QT += network
