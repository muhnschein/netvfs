# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../common.pri)
include(qml.pri)

TEMPLATE = lib
TARGET = netvfsaccountsplugin
QT = core qml concurrent
CONFIG += plugin hide_symbols

NETVFS_QML_MODULE_PATH = org/netvfs/accounts
DESTDIR = $$NETVFS_BUILD/qml/$$NETVFS_QML_MODULE_PATH

LIBS += $$netvfsCoreLibs()
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
