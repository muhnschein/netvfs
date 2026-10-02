# SPDX-License-Identifier: LGPL-2.1-or-later
# A QtTest executable that needs only the core library (no fake backend or
# accounts fixtures), run by "make check".
include(../common.pri)

TEMPLATE = app
QT += testlib
QT -= gui
CONFIG += testcase console
CONFIG -= app_bundle
LIBS += $$netvfsCoreLibs()
QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
# Never install test binaries.
target.path =
