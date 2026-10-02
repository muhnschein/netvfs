# SPDX-License-Identifier: LGPL-2.1-or-later
# QML module org.netvfs.accounts 1.0 (SPEC 7.2): C++ plugin plus shared pages,
# installed with the core package (SPEC 4.1). Links libnetvfs only; accounts
# and credentials are written from QML through Sailfish.Accounts (SPEC 6.3).
include(../../common.pri)
include(qml.pri)

TEMPLATE = lib
TARGET = netvfsaccountsplugin
QT = core qml concurrent
CONFIG += plugin hide_symbols

NETVFS_QML_MODULE_PATH = org/netvfs/accounts
# The module is importable from the build tree (tests use NETVFS_BUILD/qml).
DESTDIR = $$NETVFS_BUILD/qml/$$NETVFS_QML_MODULE_PATH

LIBS += $$netvfsCoreLibs()
# Tests load the plugin from the build tree; installed plugins find
# libnetvfs through the system library path (no RUNPATH in packages).
!equals(NETVFS_BUILD_TESTS, 0): QMAKE_RPATHDIR += $$NETVFS_LIB_OUT
QMAKE_LFLAGS += -Wl,--no-undefined
DEFINES += NETVFS_TRANSLATIONS_DIR=\\\"/usr/share/translations\\\"

SOURCES += plugin.cpp

for(file, NETVFS_QML_MODULE_FILES) {
    QMAKE_POST_LINK += $$QMAKE_COPY $$shell_quote($$PWD/$$file) $$shell_quote($$DESTDIR/) $$escape_expand(\\n\\t)
    OTHER_FILES += $$file
}

target.path = $$[QT_INSTALL_QML]/$$NETVFS_QML_MODULE_PATH
module.files = $$NETVFS_QML_MODULE_FILES
module.path = $$target.path
INSTALLS += target module
