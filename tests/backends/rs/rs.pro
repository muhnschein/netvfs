# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = lib plugin shim conformance
shim.file = tst_rsshim.pro
shim.depends = lib plugin
conformance.depends = lib plugin
