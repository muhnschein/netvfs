# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
include($$NETVFS_ROOT/src/backends/smb/smbhelper.pri)
TARGET = tst_smb
INCLUDEPATH += $$NETVFS_ROOT/src/backends/smb $$VENDOR_PREFIX/include
HEADERS = \
    $$NETVFS_ROOT/src/backends/smb/smbhelper.h \
    $$NETVFS_ROOT/src/backends/smb/smbshares.h \
    $$NETVFS_ROOT/src/backends/smb/smbutil.h
SOURCES = tst_smb.cpp \
    $$NETVFS_ROOT/src/backends/smb/smbhelper.cpp \
    $$NETVFS_ROOT/src/backends/smb/smbshares.cpp \
    $$NETVFS_ROOT/src/backends/smb/smbutil.cpp \
    $$NETVFS_ROOT/src/backends/smb/noshareenum.c
DEFINES += NETVFS_SMB_SHARES_HELPER=\\\"$$NETVFS_SMB_SHARES_INSTALL_DIR/netvfs-smb-shares\\\" \
    NETVFS_TEST_SHARES_HELPER=\\\"$$NETVFS_SMB_SHARES_OUT/netvfs-smb-shares\\\"
LIBS += $$VENDOR_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libsmb2.a
