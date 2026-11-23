# SPDX-License-Identifier: LGPL-2.1-or-later
TEMPLATE = aux

consumers.files = lautta.conf
consumers.path = /usr/share/netvfs/consumers

handoff.files = handoff.conf
handoff.path = /usr/share/netvfs/bridge

settingsentry.files = netvfs-access.json
settingsentry.path = /usr/share/jolla-settings/entries
settingspage.files = netvfs-access.qml
settingspage.path = /usr/share/jolla-settings/pages

INSTALLS += consumers handoff settingsentry settingspage
