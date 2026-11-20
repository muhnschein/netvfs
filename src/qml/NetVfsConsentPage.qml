// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// "Apps using network locations": apps registered for netvfs-bridge
// (/usr/share/netvfs/consumers/<id>.conf); each opens what it may do per account
// (NetVfsAccessPage). Opened from the pull-down menu of every account's settings page, and as the
// Settings entry the bridge's notification opens, which shows the request of the first app waiting
// for the user (`openRequest`).
Page {
    id: page

    // Consent file; empty: the default (~/.config/netvfs/bridge.conf).
    property alias storePath: consents.storePath
    property bool openRequest
    property bool _requested

    NetVfsConsentModel {
        id: consents
    }

    onStatusChanged: {
        if (status === PageStatus.Activating) {
            consents.reload()
        } else if (status === PageStatus.Active && openRequest && !_requested) {
            _requested = true
            var pending = consents.firstPending()
            if (pending !== "") {
                pageStack.push(requestDialog, { consumerId: pending })
            }
        }
    }

    Component {
        id: requestDialog

        NetVfsAccessRequestDialog {
            storePath: page.storePath
        }
    }

    Component {
        id: appPage

        NetVfsAccessPage {
            storePath: page.storePath
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
                //% "Allowed apps work in the accounts whose file browsing is on. They never see passwords or keys."
                text: qsTrId("settings-accounts-netvfs-la-access_explanation")
            }

            Item {
                width: 1
                height: Theme.paddingLarge
            }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeMedium
            onClicked: pageStack.push(appPage, { consumerId: model.consumerId })

            Image {
                id: icon

                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                width: Theme.iconSizeMedium
                height: width
                sourceSize.width: width
                sourceSize.height: height
                source: model.icon
            }

            Label {
                anchors {
                    left: icon.right
                    leftMargin: Theme.paddingLarge
                    right: parent.right
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
                truncationMode: TruncationMode.Fade
                text: model.displayName
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
