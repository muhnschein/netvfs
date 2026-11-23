# SPDX-License-Identifier: LGPL-2.1-or-later
include(../../../../common.pri)
include(../rstest.pri)

TEMPLATE = aux

check.commands = NETVFS_CONFORMANCE_CONFIG=$$shell_quote($$PWD/mem.json) \
    NETVFS_BACKEND_PATH=$$shell_quote($$NETVFS_LIB_OUT/netvfs/test-backends) \
    NETVFS_RS_LIB=$$shell_quote($$NETVFS_TEST_RS_LIB) \
    $$shell_quote($$NETVFS_BUILD/tests/conformance/tst_conformance)
QMAKE_EXTRA_TARGETS += check
OTHER_FILES += mem.json
