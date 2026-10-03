# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
TARGET = tst_discovery
QT += network
# Needs neither the fake backend nor its helper library.
LIBS -= -lnetvfstest
SOURCES = tst_discovery.cpp tst_dnsmessage.cpp
HEADERS = discoverytestutil.h
