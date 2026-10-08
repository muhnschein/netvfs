# SPDX-License-Identifier: LGPL-2.1-or-later
# Buteo backup plugins (SPEC 8): the static library netvfs-buteo with all the
# logic, and per provider three thin plugins plus their six profile files.
# The provider directories build independently; the package netvfs-backup
# contains both.
TEMPLATE = subdirs
SUBDIRS = lib sftp smb
sftp.depends = lib
smb.depends = lib
