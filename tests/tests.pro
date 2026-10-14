# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = common fakeplugin unit interop conformance bridge
fakeplugin.depends = common
unit.depends = common fakeplugin
interop.depends = common
bridge.depends = common fakeplugin
