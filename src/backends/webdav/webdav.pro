# SPDX-License-Identifier: LGPL-2.1-or-later
NETVFS_PROVIDER = webdav
include(../backend.pri)
include(../rs/rs.pri)

HEADERS += webdavplugin.h
SOURCES += webdavplugin.cpp
