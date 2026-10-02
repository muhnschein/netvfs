# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfs
VERSION = 1.0.0
DESTDIR = $$NETVFS_LIB_OUT

QT = core dbus network
CONFIG += hide_symbols link_pkgconfig create_pc create_prl no_install_prl
PKGCONFIG += accounts-qt5 libsignon-qt5

DEFINES += NETVFS_BUILD_CORE
DEFINES += NETVFS_BACKEND_DIR=\\\"$$NETVFS_BACKEND_INSTALL_DIR\\\"

PUBLIC_HEADERS = \
    accountsession.h \
    accountstore.h \
    backend.h \
    backendloader.h \
    boundedpipe.h \
    consentstore.h \
    discovery.h \
    discoverytransport.h \
    dnsmessage.h \
    error.h \
    identity.h \
    logging.h \
    names.h \
    netvfs_global.h \
    ops.h \
    paths.h \
    probe.h \
    secretsource.h \
    secure.h \
    sshkeys.h \
    transfer.h \
    types.h \
    url.h

HEADERS = $$PUBLIC_HEADERS \
    discoverycache.h

SOURCES = \
    accountsession.cpp \
    accountstore.cpp \
    backend.cpp \
    backendloader.cpp \
    boundedpipe.cpp \
    consentstore.cpp \
    discovery.cpp \
    discoverycache.cpp \
    discoverytransport.cpp \
    dnsmessage.cpp \
    error.cpp \
    identity.cpp \
    logging.cpp \
    names.cpp \
    ops.cpp \
    paths.cpp \
    probe.cpp \
    secretsource.cpp \
    secure.cpp \
    sshkeys.cpp \
    transfer.cpp \
    types.cpp \
    url.cpp

target.path = $$[QT_INSTALL_LIBS]
headers.files = $$PUBLIC_HEADERS
headers.path = /usr/include/netvfs
INSTALLS += target headers

QMAKE_PKGCONFIG_NAME = netvfs
QMAKE_PKGCONFIG_DESCRIPTION = Remote file access over SFTP and SMB accounts
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$headers.path
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = Qt5Core Qt5DBus Qt5Network accounts-qt5 libsignon-qt5
