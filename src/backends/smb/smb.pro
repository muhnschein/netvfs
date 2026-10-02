# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-smb.so: the SMB backend, statically containing libsmb2 (SPEC-smb).
NETVFS_PROVIDER = smb
include(../backend.pri)

HEADERS = \
    smb2api.h \
    smbbackend.h \
    smbplugin.h \
    smbutil.h

SOURCES = \
    noshareenum.cpp \
    smbbackend.cpp \
    smbplugin.cpp \
    smbutil.cpp

# SEC-7: linked statically; backend.pri hides its symbols (--exclude-libs,ALL).
LIBS += $$VENDOR_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libsmb2.a
