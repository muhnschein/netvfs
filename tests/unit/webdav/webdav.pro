# SPDX-License-Identifier: LGPL-2.1-or-later
# tst_webdav: the WebDAV backend's pure parts and its behaviour against an
# in-process HTTP(S) server. The backend sources are compiled in, with the
# test hook for a private CA file (NETVFS_TLS_TEST_HOOKS).
include(../../test.pri)
TARGET = tst_webdav
LIBS -= -lnetvfstest
DEFINES += NETVFS_TLS_TEST_HOOKS
include($$NETVFS_ROOT/src/backends/webdav/webdav.pri)
HEADERS += fakedav.h httptestserver.h testcerts.h
SOURCES += tst_webdav.cpp fakedav.cpp httptestserver.cpp testcerts.cpp
LIBS += -lpthread
