# SPDX-License-Identifier: LGPL-2.1-or-later
NETVFS_PROVIDER = sftp
include(../backend.pri)
include(../rs/rs.pri)

HEADERS += sftpplugin.h
SOURCES += sftpplugin.cpp
