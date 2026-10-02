# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-ftp.so: FTP/FTPS backend over the system libcurl (SPEC-v2 6.4).
NETVFS_PROVIDER = ftp
include(../backend.pri)

include(ftp.pri)
SOURCES += ftpplugin.cpp
