# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_interop_ftp: FTP/FTPS interop matrix (SPEC-v2 6.4, XT-1, XT-2, XT-5)
# against the servers that run.sh starts. Not a "make check" test case;
# run.sh runs it. Everything goes through the plugin in the build tree.
include(../../test.pri)
CONFIG -= testcase
LIBS -= -lnetvfstest
TARGET = tst_interop_ftp
SOURCES += tst_interop_ftp.cpp
