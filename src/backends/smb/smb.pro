# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-smb.so: the SMB backend, statically containing libsmb2 (SPEC-smb).
NETVFS_PROVIDER = smb
include(../backend.pri)
include(smbhelper.pri)

HEADERS = \
    smb2api.h \
    smbbackend.h \
    smbcallbacks.h \
    smbfiles.h \
    smbhelper.h \
    smbops.h \
    smbplugin.h \
    smbsession.h \
    smbshares.h \
    smbutil.h

SOURCES = \
    noshareenum.c \
    smbbackend.cpp \
    smbcallbacks.c \
    smbfiles.cpp \
    smbhelper.cpp \
    smbops.cpp \
    smbplugin.cpp \
    smbsession.cpp \
    smbshares.cpp \
    smbutil.cpp

DEFINES += NETVFS_SMB_SHARES_HELPER=\\\"$$NETVFS_SMB_SHARES_INSTALL_DIR/netvfs-smb-shares\\\"

# SEC-7: linked statically; backend.pri hides its symbols (--exclude-libs,ALL).
# G-SMB item 4: this is the build without libdcerpc; noshareenum.c keeps the
# share enumeration out (that runs in netvfs-smb-shares, shares/).
LIBS += $$VENDOR_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libsmb2.a
