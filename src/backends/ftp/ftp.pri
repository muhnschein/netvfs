# SPDX-License-Identifier: LGPL-2.1-or-later
# FTP backend sources; shared by the plugin and the test drivers that
# compile them in. Links the system libcurl and OpenSSL (SPEC-v2 W-1, F-1:
# part of the OS, dynamically linked, not vendored) through curlcommon.
INCLUDEPATH += $$PWD
include(../curlcommon/curlcommon.pri)
HEADERS += \
    $$PWD/ftpbackend.h \
    $$PWD/ftpconnection.h \
    $$PWD/ftphandles.h \
    $$PWD/ftpparse.h \
    $$PWD/ftpsupport.h
SOURCES += \
    $$PWD/ftpbackend.cpp \
    $$PWD/ftpconnection.cpp \
    $$PWD/ftphandles.cpp \
    $$PWD/ftpparse.cpp \
    $$PWD/ftpsupport.cpp
