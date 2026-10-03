# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_interop_webdav: run by tests/interop/webdav/run.sh against the
# containerised servers, not by "make check". The backend sources are
# compiled in with the private-CA test hook (NETVFS_TLS_TEST_HOOKS);
# pluginLoads() goes through the real plugin.
include(../../test.pri)
CONFIG -= testcase
QT += network
TARGET = tst_interop_webdav
LIBS -= -lnetvfstest
DEFINES += NETVFS_TLS_TEST_HOOKS
include($$NETVFS_ROOT/src/backends/webdav/webdav.pri)
SOURCES += tst_interop_webdav.cpp
