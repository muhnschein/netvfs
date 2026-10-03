# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = core fake transfer accounts cli buteo qml smb sftp webdav ftp
# Need only the core library (ops, bounded pipe, URLs, discovery).
SUBDIRS += ops pipe url discovery
