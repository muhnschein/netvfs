# SPDX-License-Identifier: LGPL-2.1-or-later
# Loads the built org.netvfs.accounts module in a QQmlEngine and checks the
# QML sources (syntax via qmllint, Qt 5.6 compatibility, translations,
# provider and service files).
include($$PWD/../../../test.pri)
TARGET = tst_qmlmodule
QT += qml
DEFINES += NETVFS_TEST_BUILD_DIR=\\\"$$NETVFS_BUILD\\\"
DEFINES += NETVFS_TEST_QT_BINS=\\\"$$[QT_INSTALL_BINS]\\\"
SOURCES += tst_qmlmodule.cpp
