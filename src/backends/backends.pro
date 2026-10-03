# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = subdirs
SUBDIRS = sftp smb smbshares local webdav ftp
# SPEC-v2 XM-7: the share enumeration helper (its own package, XP-1).
smbshares.subdir = smb/shares
