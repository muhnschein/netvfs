# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_conformance: the SPEC-v2 XT-1 backend conformance suite. Without
# NETVFS_CONFORMANCE_CONFIG it runs against the local backend in a temporary
# folder, as part of "make check"; the interop run.sh scripts point it at
# their containers (README.md). Links only libnetvfs and QtTest.
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

# Never install test binaries.
target.path =
