# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_interop_sftp: the SFTP matrix against the servers run.sh starts, through the SFTP plugin of the build tree. Not a "make check" test; run.sh runs it.
include(../../test.pri)
CONFIG -= testcase
TARGET = tst_interop_sftp
SOURCES += tst_interop_sftp.cpp
