# SPDX-License-Identifier: LGPL-2.1-or-later
# netvfs-bridge (SPEC-v2 section 8a): the bridge library (also linked by the
# tests), the daemon, the systemd user generator and the shipped data.
TEMPLATE = subdirs
SUBDIRS = lib app generator data
app.depends = lib
