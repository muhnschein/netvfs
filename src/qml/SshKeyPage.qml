// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import org.netvfs.accounts 1.0

// SPEC-sftp 5.1: generates or imports the account's key, shows the public
// line with "Copy to clipboard" and offers "Install on server using
// password" (S-16). The password is used once and not stored.
Dialog {
    id: dialog

    property SshKeyTool keyTool
    // "generate" or "import"
    property string keySource: "generate"
    // Connection parameters with the accepted host key (for the install)
    property var params: ({})

    property string _keyPath
    // Null-safe views of the tool, for the bindings below.
    readonly property int _state: keyTool ? keyTool.state : SshKeyTool.Empty
    readonly property int _installState: keyTool ? keyTool.installState : SshKeyTool.InstallIdle
    readonly property bool _hasKey: keyTool !== null && keyTool.hasKey
    readonly property string _publicKey: keyTool ? keyTool.publicKey : ""
    readonly property string _fingerprint: keyTool ? keyTool.fingerprint : ""
    readonly property string _errorText: keyTool ? keyTool.errorText : ""
    readonly property string _errorDetail: keyTool ? keyTool.errorDetail : ""
    readonly property string _installErrorText: keyTool ? keyTool.installErrorText : ""
    readonly property string _installErrorDetail: keyTool ? keyTool.installErrorDetail : ""

    canAccept: _hasKey && _installState !== SshKeyTool.Installing

    onStatusChanged: {
        if (status === PageStatus.Active && keySource === "generate" && keyTool
                && !keyTool.hasKey && keyTool.state !== SshKeyTool.Working) {
            keyTool.generate()
        }
    }

    Component {
        id: filePickerComponent

        FilePickerPage {
            //% "Choose the private key file"
            title: qsTrId("settings-accounts-netvfs-he-choose_key_file")
            onSelectedContentPropertiesChanged: {
                dialog._keyPath = selectedContentProperties.filePath
                dialog.keyTool.importFile(dialog._keyPath, "")
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                //% "Continue"
                acceptText: qsTrId("settings-accounts-netvfs-bt-continue")
            }

            Button {
                visible: dialog.keySource === "import" && dialog._state !== SshKeyTool.Working
                anchors.horizontalCenter: parent.horizontalCenter
                text: dialog._hasKey
                      ? //% "Choose another key file"
                        qsTrId("settings-accounts-netvfs-bt-choose_other_key_file")
                      : //% "Choose key file"
                        qsTrId("settings-accounts-netvfs-bt-choose_key_file")
                onClicked: pageStack.push(filePickerComponent)
            }

            Row {
                visible: dialog._state === SshKeyTool.Working
                x: Theme.horizontalPageMargin
                spacing: Theme.paddingMedium

                BusyIndicator {
                    size: BusyIndicatorSize.Small
                    running: parent.visible
                    anchors.verticalCenter: parent.verticalCenter
                }

                Label {
                    anchors.verticalCenter: parent.verticalCenter
                    color: Theme.highlightColor
                    //% "Preparing the key"
                    text: qsTrId("settings-accounts-netvfs-la-preparing_key")
                }
            }

            PasswordField {
                id: passphraseField

                visible: dialog._state === SshKeyTool.NeedsPassphrase
                width: parent.width
                //% "Passphrase of the key file"
                label: qsTrId("settings-accounts-netvfs-la-key_passphrase")
                placeholderText: label
                errorHighlight: dialog._errorText !== ""
                description: dialog._errorText
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: {
                    dialog.keyTool.importFile(dialog._keyPath, text)
                    text = ""
                }
            }

            Label {
                visible: dialog._state === SshKeyTool.Failed
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: dialog._errorText
                      + (dialog._errorDetail !== "" ? "\n" + dialog._errorDetail : "")
            }

            Column {
                visible: dialog._hasKey
                width: parent.width
                spacing: Theme.paddingMedium

                SectionHeader {
                    //% "Public key"
                    text: qsTrId("settings-accounts-netvfs-he-public_key")
                }

                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryHighlightColor
                    //% "Add this line to ~/.ssh/authorized_keys on the server, or install it below with the account's password."
                    text: qsTrId("settings-accounts-netvfs-la-public_key_explanation")
                }

                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    wrapMode: Text.WrapAnywhere
                    font.family: "monospace"
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.highlightColor
                    text: dialog._publicKey
                }

                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    wrapMode: Text.WrapAnywhere
                    font.family: "monospace"
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: dialog._fingerprint
                }

                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    //% "Copy to clipboard"
                    text: qsTrId("settings-accounts-netvfs-bt-copy_public_key")
                    onClicked: Clipboard.text = dialog._publicKey
                }

                SectionHeader {
                    //% "Install on server"
                    text: qsTrId("settings-accounts-netvfs-he-install_key")
                }

                PasswordField {
                    id: installPasswordField

                    width: parent.width
                    //% "Password for this one sign-in (not stored)"
                    label: qsTrId("settings-accounts-netvfs-la-install_password")
                    placeholderText: label
                    enabled: dialog._installState !== SshKeyTool.Installing
                }

                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    enabled: installPasswordField.text.length > 0
                             && dialog._installState !== SshKeyTool.Installing
                    //% "Install on server using password"
                    text: qsTrId("settings-accounts-netvfs-bt-install_key")
                    onClicked: {
                        dialog.keyTool.installWithPassword(dialog.params, installPasswordField.text)
                        installPasswordField.text = ""
                    }
                }

                Row {
                    visible: dialog._installState === SshKeyTool.Installing
                    x: Theme.horizontalPageMargin
                    spacing: Theme.paddingMedium

                    BusyIndicator {
                        size: BusyIndicatorSize.Small
                        running: parent.visible
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Label {
                        anchors.verticalCenter: parent.verticalCenter
                        color: Theme.highlightColor
                        //% "Installing the key"
                        text: qsTrId("settings-accounts-netvfs-la-installing_key")
                    }
                }

                Label {
                    visible: dialog._installState === SshKeyTool.Installed
                             || dialog._installState === SshKeyTool.InstallFailed
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    wrapMode: Text.Wrap
                    color: dialog._installState === SshKeyTool.Installed ? Theme.highlightColor
                                                                               : Theme.errorColor
                    text: dialog._installState === SshKeyTool.Installed
                          ? //% "The key was added to ~/.ssh/authorized_keys on the server."
                            qsTrId("settings-accounts-netvfs-la-key_installed")
                          : dialog._installErrorText
                            + (dialog._installErrorDetail !== "" ? "\n" + dialog._installErrorDetail : "")
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
