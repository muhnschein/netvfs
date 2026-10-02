# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-webdav.so: the WebDAV backend over the system libcurl (SPEC-v2 6.3).
NETVFS_PROVIDER = webdav
include(../backend.pri)
include(webdav.pri)

HEADERS += webdavplugin.h
SOURCES += webdavplugin.cpp
