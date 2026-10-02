# SPDX-License-Identifier: LGPL-2.1-or-later
# FTP backend logic that needs no server (SPEC-v2 6.4): reply, FEAT, MLSx
# and LIST parsers, path and URL encoding, error mapping, the TLS guard and
# the shared TLS identity code over certificates made by the test. Built
# with the test hook for a private CA file (NETVFS_TLS_TEST_HOOKS).
include(../../test.pri)
LIBS -= -lnetvfstest
TARGET = tst_ftp
DEFINES += NETVFS_TLS_TEST_HOOKS
include($$NETVFS_ROOT/src/backends/curlcommon/curlcommon.pri)
INCLUDEPATH += $$NETVFS_ROOT/src/backends/ftp
HEADERS += \
    $$NETVFS_ROOT/src/backends/ftp/ftpparse.h \
    $$NETVFS_ROOT/src/backends/ftp/ftpsupport.h
SOURCES += tst_ftp.cpp \
    $$NETVFS_ROOT/src/backends/ftp/ftpparse.cpp \
    $$NETVFS_ROOT/src/backends/ftp/ftpsupport.cpp
