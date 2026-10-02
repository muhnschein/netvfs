# SPDX-License-Identifier: LGPL-2.1-or-later
# qmake variable NETVFS_BUILD_TESTS=0 skips the tests (package builds).
TEMPLATE = subdirs
SUBDIRS = src accounts
!equals(NETVFS_BUILD_TESTS, 0) {
    SUBDIRS += tests
    tests.depends = src
}
OTHER_FILES += rpm/netvfs.spec
