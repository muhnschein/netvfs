# SPDX-License-Identifier: LGPL-2.1-or-later
# SMB interop driver: run by tests/interop/smb/run.sh against containerised
# Samba servers, not by "make check".
include(../../test.pri)
CONFIG -= testcase
TARGET = tst_interop_smb
INCLUDEPATH += $$NETVFS_ROOT/src/backends/smb $$VENDOR_PREFIX/include
SOURCES = tst_interop_smb.cpp \
    $$NETVFS_ROOT/src/backends/smb/smbshares.cpp
# M-T7 and the M-5 check drive libsmb2 directly; the plugin has its own hidden copy.
LIBS += $$VENDOR_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libsmb2.a
