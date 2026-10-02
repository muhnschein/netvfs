// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// Input dialog of the creation flow (SPEC 7.3 step 1) with the fields of
// SPEC-sftp 1 and SPEC-smb 1. With credentialsOnly set it asks only for the
// secret, for the credentials update flow (SPEC 7.5; for SFTP the three
// choices of S-18: password, new key, imported key).
// Input is validated by NetVfsHelpers before any connection is made (M-9).
Dialog {
    id: dialog

    property string provider
    property bool credentialsOnly
    // "password" or "publickey"; preselects the sign-in method
    property string initialAuthMode: "password"

    readonly property bool isSftp: provider === "sftp"
    readonly property bool isSmb: provider === "smb"
    readonly property string authMode: isSftp && methodBox.currentIndex > 0 ? "publickey" : "password"
    // "generate" or "import" (key mode only)
    readonly property string keySource: methodBox.currentIndex === 2 ? "import" : "generate"
    readonly property string password: passwordField.text
    readonly property string backupsPath: NetVfsHelpers.cleanBackupsPath(provider, backupsField.text)

    readonly property string hostProblem: NetVfsHelpers.hostProblem(hostField.text)
    readonly property string portProblem: NetVfsHelpers.portProblem(portField.text)
    readonly property string userProblem: NetVfsHelpers.userNameProblem(userField.text)
    readonly property string shareProblem: isSmb ? NetVfsHelpers.shareProblem(shareField.text) : ""
    readonly property string folderProblem: NetVfsHelpers.backupsPathProblem(provider, backupsField.text)
    readonly property bool passwordMissing: authMode === "password" && passwordField.text.length === 0
    readonly property bool connectionValid: hostProblem === "" && portProblem === "" && userProblem === ""
                                            && shareProblem === "" && folderProblem === ""

    // Connection parameters for NetVfsProbe and NetVfsAccountSetup;
    // `hostKey` is the accepted pin (SFTP), or "".
    function connectionParams(hostKey) {
        var options = {}
        if (isSftp) {
            options["auth_mode"] = authMode
            if (hostKey.length > 0) {
                options["host_key"] = hostKey
            }
        }
        if (isSmb) {
            options["share"] = shareField.text.trim()
            options["domain"] = domainField.text.trim()
            options["require_encryption"] = encryptionSwitch.checked
        }
        return NetVfsHelpers.makeParams(provider, hostField.text, portField.text, userField.text, options)
    }

    function clearPassword() {
        passwordField.text = ""
    }

    canAccept: !passwordMissing && (credentialsOnly || connectionValid)

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                acceptText: dialog.credentialsOnly
                            ? //% "Continue"
                              qsTrId("settings-accounts-netvfs-bt-continue")
                            : //% "Connect"
                              qsTrId("settings-accounts-netvfs-bt-connect")
            }

            TextField {
                id: hostField

                visible: !dialog.credentialsOnly
                width: parent.width
                //% "Server"
                label: qsTrId("settings-accounts-netvfs-la-server")
                //% "Server name or IP address"
                placeholderText: qsTrId("settings-accounts-netvfs-ph-server")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                errorHighlight: text.length > 0 && dialog.hostProblem !== ""
                description: errorHighlight ? dialog.hostProblem : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: portField.focus = true
            }

            TextField {
                id: portField

                visible: !dialog.credentialsOnly
                width: parent.width
                //% "Port"
                label: qsTrId("settings-accounts-netvfs-la-port")
                text: NetVfsHelpers.defaultPort(dialog.provider) > 0
                      ? String(NetVfsHelpers.defaultPort(dialog.provider)) : ""
                inputMethodHints: Qt.ImhDigitsOnly
                errorHighlight: dialog.portProblem !== ""
                description: dialog.portProblem
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: (dialog.isSmb ? shareField : userField).focus = true
            }

            TextField {
                id: shareField

                visible: dialog.isSmb && !dialog.credentialsOnly
                width: parent.width
                //% "Share"
                label: qsTrId("settings-accounts-netvfs-la-share")
                //% "Name of the shared folder on the server"
                placeholderText: qsTrId("settings-accounts-netvfs-ph-share")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                errorHighlight: text.length > 0 && dialog.shareProblem !== ""
                description: errorHighlight ? dialog.shareProblem : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: userField.focus = true
            }

            TextField {
                id: userField

                visible: !dialog.credentialsOnly
                width: parent.width
                //% "User name"
                label: qsTrId("settings-accounts-netvfs-la-user")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                errorHighlight: text.length > 0 && dialog.userProblem !== ""
                description: errorHighlight ? dialog.userProblem : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: (dialog.isSmb ? domainField : passwordField).focus = true
            }

            TextField {
                id: domainField

                visible: dialog.isSmb && !dialog.credentialsOnly
                width: parent.width
                //% "Domain or workgroup (optional)"
                label: qsTrId("settings-accounts-netvfs-la-domain")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passwordField.focus = true
            }

            ComboBox {
                id: methodBox

                visible: dialog.isSftp
                width: parent.width
                //% "Sign-in method"
                label: qsTrId("settings-accounts-netvfs-la-sign_in_method")
                currentIndex: dialog.initialAuthMode === "publickey" ? 1 : 0
                menu: ContextMenu {
                    MenuItem {
                        //% "Password"
                        text: qsTrId("settings-accounts-netvfs-me-password")
                    }
                    MenuItem {
                        //% "SSH key: generate a new key"
                        text: qsTrId("settings-accounts-netvfs-me-key_generate")
                    }
                    MenuItem {
                        //% "SSH key: import a key file"
                        text: qsTrId("settings-accounts-netvfs-me-key_import")
                    }
                }
            }

            PasswordField {
                id: passwordField

                visible: dialog.authMode === "password"
                width: parent.width
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: {
                    if (dialog.canAccept) {
                        dialog.accept()
                    }
                }
            }

            Label {
                // SPEC-smb 3: the one-line warning about NTLM challenge responses.
                visible: dialog.isSmb
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                //% "Use a strong password that you use nowhere else: any server this account connects to can try to guess it."
                text: qsTrId("settings-accounts-netvfs-la-smb_password_warning")
            }

            Label {
                visible: dialog.authMode === "publickey"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                //% "After checking the server's identity you can copy the public key, or install it on the server with your password."
                text: qsTrId("settings-accounts-netvfs-la-key_mode_hint")
            }

            TextSwitch {
                id: encryptionSwitch

                // SPEC-smb M-3
                visible: dialog.isSmb && !dialog.credentialsOnly
                checked: true
                //% "Require encryption"
                text: qsTrId("settings-accounts-netvfs-la-require_encryption")
                description: checked
                             ? //% "Connect only if the server encrypts the connection (SMB 3)."
                               qsTrId("settings-accounts-netvfs-la-require_encryption_on")
                             : //% "Servers without SMB 3 encryption are accepted. Backups are then signed, not encrypted, on the network."
                               qsTrId("settings-accounts-netvfs-la-require_encryption_off")
            }

            TextField {
                id: backupsField

                visible: !dialog.credentialsOnly
                width: parent.width
                //% "Backups folder"
                label: qsTrId("settings-accounts-netvfs-la-backups_folder")
                text: NetVfsHelpers.defaultBackupsPath
                inputMethodHints: Qt.ImhNoPredictiveText
                errorHighlight: dialog.folderProblem !== ""
                description: errorHighlight
                             ? dialog.folderProblem
                             : (dialog.isSmb
                                ? //% "Inside the share."
                                  qsTrId("settings-accounts-netvfs-la-folder_in_share")
                                : //% "Relative to the home folder, or starting with / for an absolute path."
                                  qsTrId("settings-accounts-netvfs-la-folder_in_home"))
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
        }

        VerticalScrollDecorator {}
    }
}
