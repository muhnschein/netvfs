# SPDX-License-Identifier: LGPL-2.1-or-later
# A QtTest executable run by "make check".
include(../common.pri)

TEMPLATE = app
QT += testlib concurrent
QT -= gui
CONFIG += testcase console
CONFIG -= app_bundle
INCLUDEPATH += $$NETVFS_ROOT/tests/common
LIBS += -L$$NETVFS_LIB_OUT -lnetvfstest $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
DEFINES += NETVFS_TEST_BACKEND_DIR=\\\"$$NETVFS_BACKEND_OUT\\\"
DEFINES += NETVFS_TEST_FAKE_BACKEND_DIR=\\\"$$NETVFS_LIB_OUT/netvfs/test-backends\\\"
DEFINES += NETVFS_SOURCE_DIR=\\\"$$NETVFS_ROOT\\\"
# Never install test binaries.
target.path =
