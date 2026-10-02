# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared by the libcurl based backends (WebDAV, FTP) and their tests,
# compiled into each plugin: the process-wide libcurl initialisation with
# wiping allocators (SEC-5) and the TLS server identity (XC-16, W-3, W-4).
# SPEC-v2 W-1: system libcurl, linked dynamically (part of the OS, gets its
# security updates; amends P-1); OpenSSL for the certificate details.
#
# Test hook: with DEFINES += NETVFS_TLS_TEST_HOOKS (test binaries only, never
# the plugins) the backends honour the option "test_ca_file", a CA file that
# replaces the system trust anchors.
CONFIG += link_pkgconfig
PKGCONFIG += libcurl openssl
INCLUDEPATH += $$PWD

HEADERS += \
    $$PWD/curlglobal.h \
    $$PWD/tlsidentity.h \
    $$PWD/tlsprobe.h

SOURCES += \
    $$PWD/curlglobal.c \
    $$PWD/tlsidentity.cpp \
    $$PWD/tlsprobe.cpp
