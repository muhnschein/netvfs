# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = core backends buteo qml cli
backends.depends = core
buteo.depends = core
qml.depends = core
cli.depends = core
