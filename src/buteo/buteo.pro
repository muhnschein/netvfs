# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = lib sftp smb webdav ftps
sftp.depends = lib
smb.depends = lib
webdav.depends = lib
ftps.depends = lib
