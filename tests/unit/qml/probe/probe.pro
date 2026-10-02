# SPDX-License-Identifier: LGPL-2.1-or-later
include(../qmltest.pri)
TARGET = tst_qmlprobe
CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5
SOURCES += tst_qmlprobe.cpp
