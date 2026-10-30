# SPDX-License-Identifier: LGPL-2.1-or-later
# Buteo backup plugins: static library netvfs-buteo with all the logic; per provider three thin
# plugins plus their six profile files. Provider directories build independently; package
# netvfs-backup contains both.
TEMPLATE = subdirs
SUBDIRS = lib sftp smb
sftp.depends = lib
smb.depends = lib
