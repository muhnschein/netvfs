# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_interop_sftp: the SPEC-sftp section 8 matrix against the servers that
# run.sh starts. Not a "make check" test case; run.sh runs it. Everything
# goes through the SFTP plugin of the build tree.
include(../../test.pri)
CONFIG -= testcase
TARGET = tst_interop_sftp
SOURCES += tst_interop_sftp.cpp
