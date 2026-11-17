# SPDX-License-Identifier: LGPL-2.1-or-later
NETVFS_PROVIDER = local
include(../backend.pri)

# Offsets beyond 2 GiB on 32-bit targets (armv7hl, i486).
DEFINES += _FILE_OFFSET_BITS=64

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
