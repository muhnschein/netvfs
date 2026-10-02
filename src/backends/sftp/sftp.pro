# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfs-sftp.so: SFTP backend and SSH key tools over a static libssh
# (SPEC-sftp; P-2: OpenSSL backend, dynamic platform libcrypto).
NETVFS_PROVIDER = sftp
include(../backend.pri)

include(sftp.pri)
HEADERS += sftpentry.h
SOURCES += sftpentry.cpp sftpplugin.cpp

LIBS += $$VENDOR_PREFIX/lib/libssh.a -lcrypto -lpthread
PRE_TARGETDEPS += $$VENDOR_PREFIX/lib/libssh.a
