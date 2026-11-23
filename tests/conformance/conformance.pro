# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../common.pri)

TEMPLATE = app
TARGET = tst_conformance
QT = core testlib
CONFIG += testcase console
CONFIG -= app_bundle
LIBS += $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
DEFINES += NETVFS_TEST_BACKEND_DIR=\\\"$$NETVFS_BACKEND_OUT\\\"

HEADERS = \
    support.h \
    target.h

SOURCES = \
    support.cpp \
    target.cpp \
    tst_conformance.cpp

target.path =
