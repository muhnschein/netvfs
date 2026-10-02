# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_interop_sftp: the SPEC-sftp section 8 matrix against the servers that
# run.sh starts. Not a "make check" test case; run.sh runs it. The backend
# sources are compiled in as well, for the S-T4 key exchange restriction
# that production code must not offer; everything else goes through the
# plugin in the build tree.
include(../../test.pri)
CONFIG -= testcase
TARGET = tst_interop_sftp
include($$NETVFS_ROOT/src/backends/sftp/sftp.pri)
LIBS += $$VENDOR_PREFIX/lib/libssh.a -lcrypto -lpthread
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libssh.a
SOURCES += tst_interop_sftp.cpp
