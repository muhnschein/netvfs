# SPDX-License-Identifier: LGPL-2.1-or-later
# Unit tests of the org.netvfs.accounts plugin: the plugin's C++ sources are
# compiled into the test, translations and the importable module come from the
# build tree.
include($$PWD/../../test.pri)
include($$NETVFS_ROOT/src/qml/qml.pri)

DEFINES += NETVFS_TEST_BUILD_DIR=\\\"$$NETVFS_BUILD\\\"
