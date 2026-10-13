# SPDX-License-Identifier: LGPL-2.1-or-later
include(../bridge.pri)
TARGET = tst_bridgeaccounts
PKGCONFIG += sqlite3
HEADERS += referencehelper.h
SOURCES += tst_bridgeaccounts.cpp referencehelper.cpp
