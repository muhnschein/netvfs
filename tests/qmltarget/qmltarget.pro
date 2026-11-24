# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = core qml qmlcheck
core.subdir = ../../src/core
qml.subdir = ../../src/qml
qml.depends = core
