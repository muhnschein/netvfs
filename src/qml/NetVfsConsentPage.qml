// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// SPEC-v2 XB-6: "Apps using network locations". Lists the apps registered
// for netvfs-bridge (/usr/share/netvfs/consumers/<id>.conf) with the user's
// consent from ~/.config/netvfs/bridge.conf, and grants or revokes it.
// Writing the file is the whole contract: a running bridge watches it and
// closes a revoked app's connections immediately.
//
// Reachable from the pull-down menu of every netvfs account's settings page
// (NetVfsSettingsPage). The page needs no properties, so it can also be
// opened on its own, for example from the bridge's consent notification:
// it is installed as <qml import dir>/org/netvfs/accounts/NetVfsConsentPage.qml
// and opened through the settings application's page-opening entry point
// (SPEC-v2 open question 4 decides which one on 5.2).
Page {
    id: page

    // Consent file; empty: the default (~/.config/netvfs/bridge.conf).
    property alias storePath: consents.storePath

    NetVfsConsentModel {
        id: consents
    }

    onStatusChanged: {
        if (status === PageStatus.Activating) {
            consents.reload()
        }
    }

    SilicaListView {
        id: list

        anchors.fill: parent
        model: consents

        header: Column {
            width: list.width

            PageHeader {
                //% "Apps using network locations"
                title: qsTrId("settings-accounts-netvfs-he-consent_page")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                font.pixelSize: Theme.fontSizeSmall
                //% "Allowed apps can browse, open and save files in the accounts whose file browsing is on. They never see passwords or keys."
                text: qsTrId("settings-accounts-netvfs-la-consent_explanation")
            }

            Item {
                width: 1
                height: Theme.paddingLarge
            }
        }

        delegate: TextSwitch {
            width: list.width
            automaticCheck: false
            checked: model.consent === "granted"
            text: model.displayName
            description: {
                if (model.consent === "granted") {
                    //% "Allowed"
                    return qsTrId("settings-accounts-netvfs-la-consent_granted")
                }
                if (model.consent === "denied") {
                    //% "Not allowed"
                    return qsTrId("settings-accounts-netvfs-la-consent_denied")
                }
                //% "Not asked yet"
                return qsTrId("settings-accounts-netvfs-la-consent_unknown")
            }
            onClicked: {
                if (checked) {
                    consents.revoke(model.consumerId)
                } else {
                    consents.grant(model.consumerId)
                }
            }
        }

        ViewPlaceholder {
            enabled: list.count === 0
            //% "No apps use network locations"
            text: qsTrId("settings-accounts-netvfs-la-consent_none")
        }

        VerticalScrollDecorator {}
    }
}
