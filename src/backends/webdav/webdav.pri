# SPDX-License-Identifier: LGPL-2.1-or-later
# Sources of the WebDAV backend (SPEC-v2 6.3), shared by the plugin, its unit
# tests and the interop driver. W-1: system libcurl, linked dynamically (it
# is part of the OS and gets its security updates; amends P-1); OpenSSL for
# the certificate details (XC-16).
CONFIG += link_pkgconfig
PKGCONFIG += libcurl openssl
INCLUDEPATH += $$PWD

HEADERS += \
    $$PWD/davclient.h \
    $$PWD/davconfig.h \
    $$PWD/davglobal.h \
    $$PWD/davhandles.h \
    $$PWD/davio.h \
    $$PWD/davlog.h \
    $$PWD/davstatus.h \
    $$PWD/davtls.h \
    $$PWD/davurl.h \
    $$PWD/davxml.h \
    $$PWD/webdavbackend.h

SOURCES += \
    $$PWD/davclient.cpp \
    $$PWD/davconfig.cpp \
    $$PWD/davglobal.c \
    $$PWD/davhandles.cpp \
    $$PWD/davio.cpp \
    $$PWD/davlog.cpp \
    $$PWD/davstatus.cpp \
    $$PWD/davtls.cpp \
    $$PWD/davurl.cpp \
    $$PWD/davxml.cpp \
    $$PWD/webdavbackend.cpp
