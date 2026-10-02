# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-smb-shares (SPEC-v2 XM-7): the share enumeration helper of the SMB
# backend's server mode, packaged separately (XP-1, XP-3).
include(../../../../common.pri)
include(../smbhelper.pri)

TEMPLATE = app
TARGET = netvfs-smb-shares
DESTDIR = $$NETVFS_SMB_SHARES_OUT
QT = core
CONFIG += console
CONFIG -= app_bundle
LIBS += $$netvfsCoreLibs()
# Tests run the helper from the build tree; the installed helper finds
# libnetvfs through the system library path (no RUNPATH in packages).
!equals(NETVFS_BUILD_TESTS, 0): QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
QMAKE_LFLAGS += -Wl,--exclude-libs,ALL

# The second libsmb2 build, with DCE/RPC (vendor/build-vendor.sh, variant
# "dcerpc"); the plugin's copy has neither it nor the enumeration.
SMB_DCERPC_PREFIX = $$VENDOR_PREFIX/dcerpc
INCLUDEPATH += $$PWD/.. $$SMB_DCERPC_PREFIX/include

HEADERS = \
    ../smb2api.h \
    ../smbshares.h \
    ../smbutil.h

SOURCES = \
    main.cpp \
    ../smbshares.cpp \
    ../smbutil.cpp

LIBS += $$SMB_DCERPC_PREFIX/lib/libsmb2.a
PRE_TARGETDEPS += $$SMB_DCERPC_PREFIX/lib/libsmb2.a

target.path = $$NETVFS_SMB_SHARES_INSTALL_DIR
INSTALLS += target
