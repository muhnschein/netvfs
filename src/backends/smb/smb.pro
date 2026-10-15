# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-smb.so: the SMB backend (SPEC-smb), provider "smb" of
# libnetvfs-rs.so (rust/netvfs-smb) through the shim (src/backends/rs/rs.pri).
NETVFS_PROVIDER = smb
include(../backend.pri)
include(../rs/rs.pri)

HEADERS += smbplugin.h
SOURCES += smbplugin.cpp
