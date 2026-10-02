# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = core transfer accounts cli buteo qml smb sftp
# Helpers that need only the core library (ops, bounded pipe, URLs).
SUBDIRS += pipe url
