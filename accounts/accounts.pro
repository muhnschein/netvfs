# SPDX-License-Identifier: LGPL-2.1-or-later
# Account provider files, UI files and icons (SPEC 4.1). Everything is named
# per provider so that the RPM packages each provider separately. The
# "<p>-files" services (SPEC-v2 XA-1) and the provider descriptors (XA-5)
# have their own directories and install targets (packages
# netvfs-files-services and netvfs-ui, XP-1).
TEMPLATE = subdirs
SUBDIRS = files.pro icons files-services descriptors
