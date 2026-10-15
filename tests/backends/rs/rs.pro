# SPDX-License-Identifier: LGPL-2.1-or-later
# The C++ shim of the Rust backends (src/backends/rs) against the mem
# backend of libnetvfs-rs.so built with its "testing" feature (lib): the
# test plugin libnetvfs-mem.so (plugin), tst_rsshim, and the conformance
# suite on mem through the shim (conformance). Design §6.1, §6.3.
TEMPLATE = subdirs
SUBDIRS = lib plugin shim conformance
shim.file = tst_rsshim.pro
shim.depends = lib plugin
conformance.depends = lib plugin
