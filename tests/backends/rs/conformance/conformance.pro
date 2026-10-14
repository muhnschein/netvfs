# SPDX-License-Identifier: LGPL-2.1-or-later
# The conformance suite (tests/conformance) on the mem backend of
# libnetvfs-rs.so, through the shim and the test plugin libnetvfs-mem.so
# (design §6.1), as one more "make check" run of tst_conformance. mem.json:
# a store of its own, and a stall proxy that is the same backend with the
# option stall=true (every call after authenticate waits for cancel).
include(../../../../common.pri)
include(../rstest.pri)

TEMPLATE = aux

check.commands = NETVFS_CONFORMANCE_CONFIG=$$shell_quote($$PWD/mem.json) \
    NETVFS_BACKEND_PATH=$$shell_quote($$NETVFS_LIB_OUT/netvfs/test-backends) \
    NETVFS_RS_LIB=$$shell_quote($$NETVFS_TEST_RS_LIB) \
    $$shell_quote($$NETVFS_BUILD/tests/conformance/tst_conformance)
QMAKE_EXTRA_TARGETS += check
OTHER_FILES += mem.json
