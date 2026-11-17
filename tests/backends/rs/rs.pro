# SPDX-License-Identifier: LGPL-2.1-or-later
# C++ shim of the Rust backends against the mem backend of libnetvfs-rs.so ("testing" feature, lib): test plugin libnetvfs-mem.so (plugin), tst_rsshim, conformance suite on mem through the shim (conformance).
TEMPLATE = subdirs
SUBDIRS = lib plugin shim conformance
shim.file = tst_rsshim.pro
shim.depends = lib plugin
conformance.depends = lib plugin
