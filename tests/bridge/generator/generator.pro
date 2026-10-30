# SPDX-License-Identifier: LGPL-2.1-or-later
# systemd user generator.
include(../../test.pri)
TARGET = tst_generator
DEFINES += NETVFS_TEST_BIN_DIR=\\\"$$NETVFS_BUILD/bin\\\"
SOURCES += tst_generator.cpp
