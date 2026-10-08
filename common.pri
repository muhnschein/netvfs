# SPDX-License-Identifier: LGPL-2.1-or-later
# Shared build settings. Variables that may be set on the qmake command line:
#   VENDOR_PREFIX    prefix holding the static libssh and libsmb2 (vendor/build-vendor.sh)
#   NETVFS_SANITIZE  1: AddressSanitizer + UndefinedBehaviorSanitizer
#   NETVFS_COVERAGE  1: gcov instrumentation
#   NETVFS_WERROR    1: warnings are errors

isEmpty(VENDOR_PREFIX): VENDOR_PREFIX = $$NETVFS_BUILD/vendor

# Qt 5.6 qmake knows no c++17 switch; the target gcc 13 defaults to gnu++17.
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
    # netvfs-accounts' Landlock rules let gcov write its counters here.
    DEFINES += NETVFS_COVERAGE_DIR=\\\"$$NETVFS_BUILD\\\"
}

NETVFS_LIB_OUT = $$NETVFS_BUILD/lib
NETVFS_BACKEND_OUT = $$NETVFS_LIB_OUT/netvfs/backends
NETVFS_BACKEND_INSTALL_DIR = $$[QT_INSTALL_LIBS]/netvfs/backends

INCLUDEPATH += $$NETVFS_ROOT/src/core

# Links the core library.
defineReplace(netvfsCoreLibs) {
    return(-L$$NETVFS_LIB_OUT -lnetvfs)
}
