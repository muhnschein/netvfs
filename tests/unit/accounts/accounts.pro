# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
TARGET = tst_accounts
CONFIG += link_pkgconfig
PKGCONFIG += accounts-qt5 libsignon-qt5
SOURCES = tst_accounts.cpp
