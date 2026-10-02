# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
TARGET = tst_smb
INCLUDEPATH += $$NETVFS_ROOT/src/backends/smb $$VENDOR_PREFIX/include
HEADERS = $$NETVFS_ROOT/src/backends/smb/smbutil.h
SOURCES = tst_smb.cpp \
    $$NETVFS_ROOT/src/backends/smb/smbutil.cpp \
    $$NETVFS_ROOT/src/backends/smb/noshareenum.c
LIBS += $$VENDOR_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libsmb2.a
