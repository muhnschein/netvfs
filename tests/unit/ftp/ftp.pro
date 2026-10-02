# SPDX-License-Identifier: LGPL-2.1-or-later
# FTP backend logic that needs no server (SPEC-v2 6.4): reply, FEAT, MLSx
# and LIST parsers, path and URL encoding, error mapping, the TLS guard and
# the TLS identity evaluation over certificates made by the test.
include(../../test.pri)
LIBS -= -lnetvfstest
TARGET = tst_ftp
CONFIG += link_pkgconfig
PKGCONFIG += libcurl libssl libcrypto
INCLUDEPATH += $$NETVFS_ROOT/src/backends/ftp
HEADERS = \
    $$NETVFS_ROOT/src/backends/ftp/curltls.h \
    $$NETVFS_ROOT/src/backends/ftp/ftpparse.h \
    $$NETVFS_ROOT/src/backends/ftp/ftpsupport.h
SOURCES = tst_ftp.cpp \
    $$NETVFS_ROOT/src/backends/ftp/curltls.cpp \
    $$NETVFS_ROOT/src/backends/ftp/ftpparse.cpp \
    $$NETVFS_ROOT/src/backends/ftp/ftpsupport.cpp
