# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../common.pri)

TEMPLATE = app
TARGET = netvfs-cli
DESTDIR = $$NETVFS_BUILD/bin
QT = core
CONFIG += console
CONFIG -= app_bundle
LIBS += $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

HEADERS = cli.h
SOURCES = cli.cpp main.cpp
