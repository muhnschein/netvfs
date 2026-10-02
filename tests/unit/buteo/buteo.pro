# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
include(../../../src/buteo/buteo.pri)

TARGET = tst_buteo
QT += dbus xml
PKGCONFIG += libsignon-qt5
# The static library first: it needs libnetvfs.
LIBS = -L$$NETVFS_LIB_OUT -lnetvfs-buteo $$LIBS
PRE_TARGETDEPS += $$NETVFS_BUTEO_LIB
DEFINES += NETVFS_TEST_BUTEO_PLUGIN_DIR=\\\"$$NETVFS_BUTEO_PLUGIN_OUT\\\"
DEFINES += NETVFS_TEST_BUTEO_BUILD_DIR=\\\"$$NETVFS_BUILD/src/buteo\\\"

HEADERS = fakebackupservice.h
SOURCES = fakebackupservice.cpp tst_buteo.cpp
