# SPDX-License-Identifier: LGPL-2.1-or-later
# FTP backend sources; shared by the plugin and the test drivers that
# compile them in. Links the system libcurl and OpenSSL (SPEC-v2 W-1, F-1:
# part of the OS, dynamically linked, not vendored).
CONFIG += link_pkgconfig
PKGCONFIG += libcurl libssl libcrypto
INCLUDEPATH += $$PWD
HEADERS += \
    $$PWD/curltls.h \
    $$PWD/ftpbackend.h \
    $$PWD/ftpconnection.h \
    $$PWD/ftphandles.h \
    $$PWD/ftpparse.h \
    $$PWD/ftpsupport.h
SOURCES += \
    $$PWD/curltls.cpp \
    $$PWD/ftpbackend.cpp \
    $$PWD/ftpconnection.cpp \
    $$PWD/ftphandles.cpp \
    $$PWD/ftpparse.cpp \
    $$PWD/ftpsupport.cpp
