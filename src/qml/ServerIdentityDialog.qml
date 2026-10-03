// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// Server identity confirmation (SPEC-sftp S-7, S-8; SPEC-v2 XA-5, XC-16).
// SSH: the key's algorithm and full SHA256 fingerprint (monospace).
// TLS: subject, issuer, validity, alternative names, the SHA-256 of the
// public key (what is pinned) and of the certificate, and the reasons this
// device does not trust it, in words. Explicit acceptance is required. With
// storedIdentity set (update flow, SPEC 7.5) the stored and the newly seen
// identity are shown together; a changed identity is never accepted
// silently (S-9).
Dialog {
    id: dialog

    // NetVfsProbe.serverIdentity: { kind, algorithm, fingerprint, pin, pinOptions, ... }
    property var identity: ({})
    // The pinned identity, for the update flow; empty object on creation
    property var storedIdentity: ({})

    readonly property bool changed: storedIdentity !== undefined && storedIdentity.fingerprint !== undefined
    readonly property bool isTls: identity !== undefined && identity.kind === "tls"
    readonly property var problemTexts: isTls && identity.problemTexts !== undefined ? identity.problemTexts : []
    readonly property var sans: isTls && identity.sans !== undefined ? identity.sans : []

    function _value(map, key) {
        return map !== undefined && map[key] !== undefined ? String(map[key]) : ""
    }

    function _keyText(map) {
        if (map === undefined || map.fingerprint === undefined) {
            return ""
        }
        if (map.kind === "tls") {
            //% "Public key SHA-256: %1"
            return qsTrId("settings-accounts-netvfs-la-tls_spki").arg(map.fingerprint)
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
                            ? (dialog.isTls
                               ? //% "Accept new certificate"
                                 qsTrId("settings-accounts-netvfs-bt-accept_new_certificate")
                               : //% "Accept new key"
                                 qsTrId("settings-accounts-netvfs-bt-accept_new_key"))
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
                      ? (dialog.isTls
                         ? //% "The server's certificate has changed"
                           qsTrId("settings-accounts-netvfs-he-certificate_changed")
                         : //% "The server's key has changed"
                           qsTrId("settings-accounts-netvfs-he-key_changed"))
                      : //% "Check the server's identity"
                        qsTrId("settings-accounts-netvfs-he-check_identity")
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
                        //% "Accept this certificate only if you know it belongs to the server, for example because the fingerprints match. It is stored with the account and checked on every connection."
                        return qsTrId("settings-accounts-netvfs-la-check_certificate_explanation")
                    }
                    //% "This is the first connection to this server. Accept its key only if the fingerprint matches the one on the server. The key is stored with the account and checked on every connection."
                    return qsTrId("settings-accounts-netvfs-la-check_identity_explanation")
                }
            }

            // TLS: why the device does not trust the certificate (XC-16 problems).
            Column {
                visible: dialog.problemTexts.length > 0
                width: parent.width

                Repeater {
                    model: dialog.problemTexts

                    Label {
                        x: Theme.horizontalPageMargin
                        width: column.width - 2 * x
                        wrapMode: Text.Wrap
                        color: Theme.errorColor
                        text: modelData
                    }
                }
            }

            Label {
                visible: dialog.isTls && dialog.identity.systemTrusted === true
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.secondaryHighlightColor
                //% "This device trusts the certificate. Pinning it means that a later replacement must be confirmed again."
                text: qsTrId("settings-accounts-netvfs-la-certificate_trusted")
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

            Column {
                visible: dialog.isTls
                width: parent.width

                DetailItem {
                    //% "Issued to"
                    label: qsTrId("settings-accounts-netvfs-la-tls_subject")
                    value: dialog._value(dialog.identity, "subject")
                }

                DetailItem {
                    //% "Issued by"
                    label: qsTrId("settings-accounts-netvfs-la-tls_issuer")
                    value: dialog._value(dialog.identity, "issuer")
                }

                DetailItem {
                    //% "Valid from"
                    label: qsTrId("settings-accounts-netvfs-la-tls_not_before")
                    value: dialog._value(dialog.identity, "notBefore")
                }

                DetailItem {
                    //% "Valid until"
                    label: qsTrId("settings-accounts-netvfs-la-tls_not_after")
                    value: dialog._value(dialog.identity, "notAfter")
                }

                DetailItem {
                    visible: dialog.sans.length > 0
                    //% "Server names"
                    label: qsTrId("settings-accounts-netvfs-la-tls_sans")
                    value: dialog.sans.join(", ")
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
                visible: dialog.isTls && dialog._value(dialog.identity, "certSha256") !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                //% "Certificate SHA-256: %1"
                text: qsTrId("settings-accounts-netvfs-la-tls_cert_sha256").arg(dialog._value(dialog.identity, "certSha256"))
            }

            Label {
                visible: !dialog.isTls
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                text: dialog.isTls ? "" : NetVfsHelpers.hostKeyHint(dialog._value(dialog.identity, "algorithm"))
            }
        }

        VerticalScrollDecorator {}
    }
}
