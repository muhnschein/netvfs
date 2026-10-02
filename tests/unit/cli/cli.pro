# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../test.pri)
TARGET = tst_cli
INCLUDEPATH += $$NETVFS_ROOT/src/cli
HEADERS = $$NETVFS_ROOT/src/cli/cli.h
SOURCES = tst_cli.cpp $$NETVFS_ROOT/src/cli/cli.cpp
