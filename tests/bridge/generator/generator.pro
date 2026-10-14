# SPDX-License-Identifier: LGPL-2.1-or-later
# The systemd user generator (SPEC-v2 XB-3, XB-4).
include(../../test.pri)
TARGET = tst_generator
DEFINES += NETVFS_TEST_BIN_DIR=\\\"$$NETVFS_BUILD/bin\\\"
SOURCES += tst_generator.cpp
