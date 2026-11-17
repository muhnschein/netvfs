// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// Server identity confirmation: key algorithm (SSH) and full SHA256 fingerprint (monospace); TLS:
// SHA256 of the certificate's public key, which is what gets pinned. Explicit acceptance required. With storedIdentity set (update flow) stored and newly seen identity are
// shown together; a changed identity is never accepted silently.
Dialog {
    id: dialog

    // NetVfsProbe.serverIdentity: { kind, algorithm, fingerprint, pin, pinOptions }
    property var identity: ({})
    // The pinned identity, for the update flow; empty object on creation
    property var storedIdentity: ({})

    readonly property bool changed: storedIdentity !== undefined && storedIdentity.fingerprint !== undefined
    readonly property bool isTls: identity !== undefined && identity.kind === "tls"

    function _value(map, key) {
        return map !== undefined && map[key] !== undefined ? String(map[key]) : ""
    }

    function _keyText(map) {
        if (map === undefined || map.fingerprint === undefined) {
            return ""
        }
        if (map.kind === "tls") {
            //% "Public key %1"
            return qsTrId("settings-accounts-netvfs-la-tls_public_key").arg(map.fingerprint)
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
                acceptText: {
                    if (!dialog.changed) {
                        //% "Trust"
                        return qsTrId("settings-accounts-netvfs-bt-trust_key")
                    }
                    return dialog.isTls
                            ? //% "Accept new certificate"
                              qsTrId("settings-accounts-netvfs-bt-accept_new_certificate")
                            : //% "Accept new key"
                              qsTrId("settings-accounts-netvfs-bt-accept_new_key")
                }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                font.pixelSize: Theme.fontSizeLarge
                text: {
                    if (!dialog.changed) {
                        //% "Check the server's identity"
                        return qsTrId("settings-accounts-netvfs-he-check_identity")
                    }
                    return dialog.isTls
                            ? //% "The server's certificate has changed"
                              qsTrId("settings-accounts-netvfs-he-certificate_changed")
                            : //% "The server's key has changed"
                              qsTrId("settings-accounts-netvfs-he-key_changed")
                }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                text: {
                    if (dialog.changed) {
                        //% "This can happen when the server was reinstalled. It can also mean that someone is intercepting the connection. Accept the new key only if you know why it changed and the fingerprint matches the one on the server."
                        return qsTrId("settings-accounts-netvfs-la-key_changed_explanation")
                    }
                    if (dialog.isTls) {
                        //% "This device does not trust the server's certificate, for example because it is self-signed. Accept it only if the fingerprint matches the server's. Its key is stored with the account and checked on every connection."
                        return qsTrId("settings-accounts-netvfs-la-check_certificate_explanation")
                    }
                    //% "This is the first connection to this server. Accept its key only if the fingerprint matches the one on the server. The key is stored with the account and checked on every connection."
                    return qsTrId("settings-accounts-netvfs-la-check_identity_explanation")
                }
            }

            SectionHeader {
                visible: dialog.changed
                text: dialog.isTls
                      ? //% "Stored certificate"
                        qsTrId("settings-accounts-netvfs-he-stored_certificate")
                      : //% "Stored key"
                        qsTrId("settings-accounts-netvfs-he-stored_key")
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
                text: {
                    if (dialog.isTls) {
                        return dialog.changed
                                ? //% "Certificate presented now"
                                  qsTrId("settings-accounts-netvfs-he-seen_certificate")
                                : //% "Server certificate"
                                  qsTrId("settings-accounts-netvfs-he-server_certificate")
                    }
                    return dialog.changed
                            ? //% "Key presented now"
                              qsTrId("settings-accounts-netvfs-he-seen_key")
                            : //% "Server key"
                              qsTrId("settings-accounts-netvfs-he-server_key")
                }
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
