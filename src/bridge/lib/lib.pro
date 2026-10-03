# SPDX-License-Identifier: LGPL-2.1-or-later
# libnetvfsbridge.a: everything of netvfs-bridge except main(), so that the
# tests run the same code in-process.
include(../../../common.pri)

TEMPLATE = lib
TARGET = netvfsbridge
CONFIG += staticlib link_pkgconfig
DESTDIR = $$NETVFS_LIB_OUT
QT = core dbus network
# libdbus directly for the consumer socket (wire.h explains why not QtDBus).
PKGCONFIG += dbus-1 accounts-qt5 libsignon-qt5
DEFINES += NETVFS_BRIDGE_VERSION=\\\"0.2.0\\\"

RESOURCES = bridge.qrc

HEADERS = \
    args.h \
    bridgelog.h \
    bridgeserver.h \
    connector.h \
    consentprompt.h \
    dbusloop.h \
    fdcheck.h \
    handoff.h \
    knownhosts.h \
    location.h \
    peercheck.h \
    pool.h \
    protocol.h \
    questions.h \
    runtime.h \
    serverparts.h \
    session.h \
    streaming.h \
    unixfd.h \
    wire.h \
    wireconnection.h \
    worker.h

SOURCES = \
    args.cpp \
    bridgeserver.cpp \
    connector.cpp \
    dbusloop.c \
    consentprompt.cpp \
    fdcheck.cpp \
    handoff.cpp \
    knownhosts.cpp \
    location.cpp \
    locationbook.cpp \
    peercheck.cpp \
    pool.cpp \
    protocol.cpp \
    questions.cpp \
    runtime.cpp \
    serverparts.cpp \
    session.cpp \
    sessionfiles.cpp \
    sessionjobs.cpp \
    streaming.cpp \
    unixfd.cpp \
    wire.cpp \
    wireconnection.cpp \
    worker.cpp

# Never installed.
target.path =
