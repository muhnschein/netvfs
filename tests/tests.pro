# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = common fakeplugin oldplugin unit interop conformance bridge
fakeplugin.depends = common
oldplugin.depends = common
unit.depends = common fakeplugin oldplugin
interop.depends = common
bridge.depends = common fakeplugin
