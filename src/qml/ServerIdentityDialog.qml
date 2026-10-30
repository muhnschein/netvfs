// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// Server identity confirmation: key algorithm and full SHA256 fingerprint (monospace). Explicit
// acceptance required. With storedIdentity set (update flow) stored and newly seen identity are
// shown together; a changed identity is never accepted silently.
Dialog {
    id: dialog

    // NetVfsProbe.serverIdentity: { algorithm, fingerprint, pin, pinOptions }
    property var identity: ({})
    // The pinned identity, for the update flow; empty object on creation
    property var storedIdentity: ({})

    readonly property bool changed: storedIdentity !== undefined && storedIdentity.fingerprint !== undefined

    function _value(map, key) {
        return map !== undefined && map[key] !== undefined ? String(map[key]) : ""
    }

    function _keyText(map) {
        if (map === undefined || map.fingerprint === undefined) {
            return ""
        }
        return map.algorithm + "\n" + map.fingerprint
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                acceptText: dialog.changed
                            ? //% "Accept new key"
                              qsTrId("settings-accounts-netvfs-bt-accept_new_key")
                            : //% "Trust"
                              qsTrId("settings-accounts-netvfs-bt-trust_key")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                font.pixelSize: Theme.fontSizeLarge
                text: dialog.changed
                      ? //% "The server's key has changed"
                        qsTrId("settings-accounts-netvfs-he-key_changed")
                      : //% "Check the server's identity"
                        qsTrId("settings-accounts-netvfs-he-check_identity")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: dialog.changed
                      ? //% "This can happen when the server was reinstalled. It can also mean that someone is intercepting the connection. Accept the new key only if you know why it changed and the fingerprint matches the one on the server."
                        qsTrId("settings-accounts-netvfs-la-key_changed_explanation")
                      : //% "This is the first connection to this server. Accept its key only if the fingerprint matches the one on the server. The key is stored with the account and checked on every connection."
                        qsTrId("settings-accounts-netvfs-la-check_identity_explanation")
            }

            SectionHeader {
                visible: dialog.changed
                //% "Stored key"
                text: qsTrId("settings-accounts-netvfs-he-stored_key")
            }

            Label {
                visible: dialog.changed
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: dialog._keyText(dialog.storedIdentity)
            }

            SectionHeader {
                text: dialog.changed
                      ? //% "Key presented now"
                        qsTrId("settings-accounts-netvfs-he-seen_key")
                      : //% "Server key"
                        qsTrId("settings-accounts-netvfs-he-server_key")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: dialog._keyText(dialog.identity)
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                text: NetVfsHelpers.hostKeyHint(dialog._value(dialog.identity, "algorithm"))
            }
        }

        VerticalScrollDecorator {}
    }
}
