# SPDX-License-Identifier: LGPL-2.1-or-later
# Target-side check of the account UI (run-in-sdk.sh): core library, QML plugin and checker, built against the target's Qt 5.6.
TEMPLATE = subdirs
SUBDIRS = core qml qmlcheck
core.subdir = ../../src/core
qml.subdir = ../../src/qml
qml.depends = core

