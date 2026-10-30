# SPDX-License-Identifier: LGPL-2.1-or-later
NETVFS_PROVIDER = smb
include(../backend.pri)
include(../rs/rs.pri)

HEADERS += smbplugin.h
SOURCES += smbplugin.cpp
