# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared test helpers (shared library so that a single FakeServer instance is
# seen by tests and by the fake backend plugin).
include(../../common.pri)

TEMPLATE = lib
TARGET = netvfstest
DESTDIR = $$NETVFS_LIB_OUT
QT = core
CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5
LIBS += $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT

HEADERS = fakebackend.h accountsfixture.h
SOURCES = fakebackend.cpp accountsfixture.cpp
