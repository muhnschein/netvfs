# SPDX-License-Identifier: LGPL-2.1-or-later
NETVFS_PROVIDER = ftps
include(../backend.pri)
include(../rs/rs.pri)

HEADERS += ftpsplugin.h
SOURCES += ftpsplugin.cpp
