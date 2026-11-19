// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// The bridge's request, opened from its notification: what one app may do on each account (all,
// or once decided only the accounts added since), stored on Save.
Dialog {
    id: dialog

    property alias consumerId: access.consumerId
    // Consent file; empty: the default (~/.config/netvfs/bridge.conf).
    property alias storePath: access.storePath

    NetVfsAccessModel {
        id: access

        request: true
        autoSave: false
    }

    onAccepted: {
        if (!access.save()) {
            console.warn("Cannot store what", access.consumerId, "may do")
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: header.height + column.height

        DialogHeader {
            id: header

            //% "Save"
            acceptText: qsTrId("settings-accounts-netvfs-he-access_save")
        }

        AccessColumn {
            id: column

            anchors.top: header.bottom
            access: access
            description: {
                if (!access.decided) {
                    return column.askedText(access.asked)
                }
                return access.count === 1
                        //% "New account since you last chose"
                        ? qsTrId("settings-accounts-netvfs-la-access_new_account")
                        //% "New accounts since you last chose"
                        : qsTrId("settings-accounts-netvfs-la-access_new_accounts")
            }
            //% "Choose what %1 may do on each account. It never sees passwords or keys. You can change this later in Settings › Accounts › Apps using network locations."
            explanation: qsTrId("settings-accounts-netvfs-la-access_request").arg(access.displayName)
        }

        VerticalScrollDecorator {}
    }
}
