# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = src tests
tests.depends = src
OTHER_FILES += rpm/netvfs.spec
