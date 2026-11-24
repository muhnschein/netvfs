# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = accounts contract generator process ffifake ffi
ffi.depends = ffifake
