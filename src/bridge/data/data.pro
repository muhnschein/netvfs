# SPDX-License-Identifier: LGPL-2.1-or-later
# Files installed with netvfs-bridge. Nothing is built.
TEMPLATE = aux

consumers.files = lautta.conf
consumers.path = /usr/share/netvfs/consumers

handoff.files = handoff.conf
handoff.path = /usr/share/netvfs/bridge

# Settings entries the request notification and AddAccount open.
settingsentry.files = netvfs-access.json netvfs-add.json
settingsentry.path = /usr/share/jolla-settings/entries
settingspage.files = netvfs-access.qml netvfs-add-sftp.qml netvfs-add-smb.qml netvfs-add-webdav.qml netvfs-add-ftps.qml
settingspage.path = /usr/share/jolla-settings/pages

INSTALLS += consumers handoff settingsentry settingspage
