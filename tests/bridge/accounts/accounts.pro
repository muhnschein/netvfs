# SPDX-License-Identifier: LGPL-2.1-or-later
# Built netvfs-accounts against the C++ reference.
include(../../test.pri)
TARGET = tst_bridgeaccounts
QT += dbus
CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5 sqlite3
DEFINES += NETVFS_TEST_LIBEXEC_DIR=\\\"$$NETVFS_BUILD/libexec/netvfs\\\"
HEADERS += referencedecoder.h referencehelper.h
SOURCES += tst_bridgeaccounts.cpp referencedecoder.cpp referencehelper.cpp
