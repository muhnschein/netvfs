# SPDX-License-Identifier: LGPL-2.1-or-later
# Buteo backup plugins (SPEC 8): the static library netvfs-buteo with all the
# logic, and per provider three thin plugins plus their six profile files.
# The provider directories build independently so that packaging can split
# them into netvfs-account-sftp and netvfs-account-smb.
TEMPLATE = subdirs
SUBDIRS = lib sftp smb
sftp.depends = lib
smb.depends = lib
