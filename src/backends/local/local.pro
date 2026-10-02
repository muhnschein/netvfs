# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-local.so: the local file system backend (SPEC-v2 section 6.5).
NETVFS_PROVIDER = local
include(../backend.pri)

HEADERS = \
    localbackend.h \
    localhandles.h \
    localplugin.h \
    localutil.h

SOURCES = \
    localbackend.cpp \
    localio.cpp \
    localplugin.cpp \
    localutil.cpp
