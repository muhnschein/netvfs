# SPDX-License-Identifier: LGPL-2.1-or-later
# Account provider files, UI files and icons, named per provider so the RPM packages each provider
# separately. "<p>-files" services and provider descriptors have their own directories and install
# targets (packages netvfs-files-services and netvfs-ui).
TEMPLATE = subdirs
SUBDIRS = files.pro icons files-services descriptors
