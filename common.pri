# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared build settings. Set on the qmake command line:
#   NETVFS_SANITIZE  1: AddressSanitizer + UndefinedBehaviorSanitizer
#   NETVFS_COVERAGE  1: gcov instrumentation
#   NETVFS_WERROR    1: warnings are errors

# Qt 5.6 qmake has no c++17 switch; target gcc 13 defaults to gnu++17.
CONFIG -= c++11 c++14
QMAKE_CXXFLAGS += -std=gnu++17
CONFIG += warn_on
QMAKE_CXXFLAGS_WARN_ON += -Wno-missing-field-initializers

equals(NETVFS_WERROR, 1): QMAKE_CXXFLAGS += -Werror

equals(NETVFS_SANITIZE, 1) {
    QMAKE_CXXFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
    QMAKE_CFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
    QMAKE_LFLAGS += -fsanitize=address,undefined
    # netvfs-accounts' Landlock rules let LeakSanitizer read its suppressions.
    DEFINES += NETVFS_SANITIZER_DIR=\\\"$$NETVFS_ROOT/tools/sanitizer\\\"
}

equals(NETVFS_COVERAGE, 1) {
    QMAKE_CXXFLAGS += --coverage -O0
    QMAKE_CFLAGS += --coverage -O0
    QMAKE_LFLAGS += --coverage
    # netvfs-accounts' Landlock rules let gcov write counters here.
    DEFINES += NETVFS_COVERAGE_DIR=\\\"$$NETVFS_BUILD\\\"
}

NETVFS_LIB_OUT = $$NETVFS_BUILD/lib
NETVFS_BACKEND_OUT = $$NETVFS_LIB_OUT/netvfs/backends
NETVFS_BACKEND_INSTALL_DIR = $$[QT_INSTALL_LIBS]/netvfs/backends

INCLUDEPATH += $$NETVFS_ROOT/src/core

defineReplace(netvfsCoreLibs) {
    return(-L$$NETVFS_LIB_OUT -lnetvfs)
}
