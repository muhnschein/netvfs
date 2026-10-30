# SPDX-License-Identifier: LGPL-2.1-or-later
INCLUDEPATH += $$PWD $$NETVFS_ROOT/src/bridge/ffi
DEFINES += NETVFS_RS_LIB_PATH=\\\"$$[QT_INSTALL_LIBS]/netvfs/libnetvfs-rs.so\\\"
LIBS += -ldl

HEADERS += \
    $$PWD/netvfs_rs.h \
    $$PWD/rsbackend.h \
    $$PWD/rshandles.h \
    $$PWD/rshooks.h \
    $$PWD/rskeytools.h \
    $$PWD/rsloader.h \
    $$PWD/rsmarshal.h

SOURCES += \
    $$NETVFS_ROOT/src/bridge/ffi/marshal.cpp \
    $$PWD/rsbackend.cpp \
    $$PWD/rshandles.cpp \
    $$PWD/rshooks.cpp \
    $$PWD/rskeytools.cpp \
    $$PWD/rsloader.cpp \
    $$PWD/rsmarshal.cpp
