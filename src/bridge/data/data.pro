# SPDX-License-Identifier: LGPL-2.1-or-later
# Files installed with netvfs-bridge (XB-3, XB-15). Nothing is built.
TEMPLATE = aux

consumers.files = lautta.conf
consumers.path = /usr/share/netvfs/consumers

handoff.files = handoff.conf
handoff.path = /usr/share/netvfs/bridge

INSTALLS += consumers handoff
