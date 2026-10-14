# SPDX-License-Identifier: LGPL-2.1-or-later
# The C++ side of the Rust backends (design §1, §2; doc/RUST.md): a backend
# plugin that serves its provider from libnetvfs-rs.so includes this and
# returns Rs::createBackend() from BackendFactory::create(). The shim links
# nothing of Rust: it loads the library with dlopen from where rs.pro
# installs it ($NETVFS_RS_LIB in tests). Phase 2's marshalling
# (src/bridge/ffi/marshal.cpp) is compiled in for the shared nvb_* types.
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
