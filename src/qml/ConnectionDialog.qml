// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// Input dialog of the creation flow (SPEC 7.3 step 1), rendered from the
// provider descriptor (SPEC-v2 XA-5, NetVfsProviders): connection fields,
// the services to set up (backup only where the provider offers it and the
// settings allow it, XA-4), the sign-in method and the secret. With
// credentialsOnly set it asks only for the sign-in method and the secret,
// for the credentials update flow (SPEC 7.5; for SFTP the choices of S-18).
// Input is validated before any connection is made (M-9).
Dialog {
    id: dialog

    property string provider
    property bool credentialsOnly
    // Preselects the sign-in method ("password", "publickey", "interactive", "token")
    property string initialAuthMode: "password"

    // { <field key>: value, auth_mode, key_source } (NetVfsProviders.initialValues)
    property var values: ({})

    readonly property var descriptor: NetVfsProviders.descriptor(provider)
    readonly property var fields: descriptor["fields"] || []
    readonly property var authModes: descriptor["authModes"] || []
    // SPEC-v2 XP-1: the backup service comes with netvfs-backup-<provider>.
    readonly property bool offersBackup: NetVfsProviders.offersService(provider, "backup")
                                         && NetVfsHelpers.isServiceInstalled(NetVfsHelpers.backupServiceName(provider))
    readonly property bool offersFiles: NetVfsProviders.offersService(provider, "files")
    readonly property bool filesInstalled: NetVfsHelpers.isServiceInstalled(NetVfsHelpers.filesServiceName(provider))

    readonly property var draftParams: NetVfsProviders.makeParams(provider, values, {})
    readonly property bool backupAllowed: NetVfsHelpers.serviceAllowed(draftParams, "backup")
    readonly property bool backupSelected: offersBackup && backupSwitch.checked && backupAllowed
    readonly property bool filesSelected: offersFiles && filesInstalled && (filesSwitch.checked || !offersBackup)
    readonly property var services: _services(backupSelected, filesSelected)

    readonly property var authModeEntry: NetVfsProviders.authMode(provider, values)
    readonly property string authMode: authModeEntry["id"] || "password"
    // "generate" or "import" (key mode only)
    readonly property string keySource: authModeEntry["source"] === "import" ? "import" : "generate"
    // "password", "token", "key" or "none" (XA-7)
    readonly property string secretKind: NetVfsProviders.secretKind(provider, values)
    readonly property string password: passwordField.text
    readonly property string backupsPath: NetVfsProviders.serviceValue(provider, values, "backups_path")
    readonly property string filesRoot: NetVfsProviders.serviceValue(provider, values, "files_root")

    readonly property bool passwordMissing: (secretKind === "password" || secretKind === "token")
                                            && passwordField.text.length === 0
    readonly property bool connectionValid: services.length > 0
                                            && NetVfsProviders.isValid(provider, values, services)

    // Connection parameters for NetVfsProbe and NetVfsAccountSetup;
    // `pinOptions` are the accepted identity's (serverIdentity.pinOptions), or {}.
    function connectionParams(pinOptions) {
        return NetVfsProviders.makeParams(provider, values, pinOptions)
    }

    function clearPassword() {
        passwordField.text = ""
    }

    function setValue(key, value) {
        if (values[key] === value) {
            return
        }
        var copy = {}
        for (var k in values) {
            copy[k] = values[k]
        }
        copy[key] = value
        values = copy
    }

    function _services(backup, files) {
        var list = []
        if (backup) {
            list.push("backup")
        }
        if (files) {
            list.push("files")
        }
        return list
    }

    function _init() {
        var initial = NetVfsProviders.initialValues(provider)
        for (var i = 0; i < authModes.length; ++i) {
            if (authModes[i]["id"] === initialAuthMode) {
                initial["auth_mode"] = initialAuthMode
                initial["key_source"] = authModes[i]["source"] || ""
                break
            }
        }
        values = initial
    }

    function _authIndex() {
        for (var i = 0; i < authModes.length; ++i) {
            if (authModes[i]["id"] === values["auth_mode"]
                    && (authModes[i]["source"] || "") === (values["key_source"] || "")) {
                return i
            }
        }
        return 0
    }

    function _selectAuthMode(index) {
        var mode = authModes[index]
        if (mode === undefined || (mode["id"] === values["auth_mode"]
                                   && (mode["source"] || "") === (values["key_source"] || ""))) {
            return
        }
        var copy = {}
        for (var k in values) {
            copy[k] = values[k]
        }
        copy["auth_mode"] = mode["id"]
        copy["key_source"] = mode["source"] || ""
        values = copy
    }

    function _choiceIndex(field) {
        var choices = field["choices"] || []
        for (var i = 0; i < choices.length; ++i) {
            if (choices[i]["value"] === values[field["key"]]) {
                return i
            }
        }
        return 0
    }

    function _text(field) {
        var value = values[field["key"]]
        return value !== undefined && value !== null ? String(value) : ""
    }

    function _inputHints(field) {
        if (field["input"] === "digits") {
            return Qt.ImhDigitsOnly
        }
        if (field["input"] === "url") {
            return Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
        }
        return Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
    }

    onProviderChanged: _init()
    Component.onCompleted: _init()

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

            Repeater {
                model: dialog.fields

                Column {
                    id: fieldItem

                    readonly property var field: modelData
                    readonly property string type: field["type"]
                    readonly property string key: field["key"]
                    // Service settings follow the service switches (second Repeater).
                    readonly property bool shown: field["service"] === undefined
                                                  && NetVfsProviders.isVisible(field, dialog.values, dialog.services)
                                                  && (!dialog.credentialsOnly || type === "note")
                    readonly property string problem: NetVfsProviders.problem(dialog.provider, field, dialog.values,
                                                                              dialog.services)
                    readonly property string description: NetVfsProviders.text(field["description"] || "")

                    visible: shown
                    width: column.width

                    TextField {
                        visible: fieldItem.type === "text"
                        width: parent.width
                        label: NetVfsProviders.text(fieldItem.field["label"])
                        placeholderText: NetVfsProviders.text(fieldItem.field["placeholder"] || fieldItem.field["label"])
                        text: dialog._text(fieldItem.field)
                        inputMethodHints: dialog._inputHints(fieldItem.field)
                        errorHighlight: text.length > 0 && fieldItem.problem !== ""
                        description: errorHighlight ? fieldItem.problem : fieldItem.description
                        onTextChanged: {
                            if (fieldItem.type === "text" && fieldItem.field["service"] === undefined) {
                                dialog.setValue(fieldItem.key, text)
                            }
                        }
                        EnterKey.iconSource: "image://theme/icon-m-enter-close"
                        EnterKey.onClicked: focus = false
                    }

                    TextSwitch {
                        visible: fieldItem.type === "switch"
                        automaticCheck: false
                        checked: dialog.values[fieldItem.key] === true
                        text: NetVfsProviders.text(fieldItem.field["label"])
                        description: fieldItem.description
                        onClicked: dialog.setValue(fieldItem.key, !checked)
                    }

                    ComboBox {
                        visible: fieldItem.type === "choice"
                        width: parent.width
                        label: NetVfsProviders.text(fieldItem.field["label"])
                        description: fieldItem.description
                        currentIndex: dialog._choiceIndex(fieldItem.field)
                        menu: ContextMenu {
                            Repeater {
                                model: fieldItem.field["choices"] || []

                                MenuItem {
                                    text: NetVfsProviders.text(modelData["label"])
                                }
                            }
                        }
                        onCurrentIndexChanged: {
                            var choices = fieldItem.field["choices"] || []
                            if (fieldItem.type === "choice" && currentIndex >= 0 && currentIndex < choices.length) {
                                dialog.setValue(fieldItem.key, choices[currentIndex]["value"])
                            }
                        }
                    }

                    Label {
                        visible: fieldItem.type === "note"
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * x
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryHighlightColor
                        text: NetVfsProviders.text(fieldItem.field["label"])
                    }
                }
            }

            ComboBox {
                id: methodBox

                visible: dialog.authModes.length > 1
                width: parent.width
                //% "Sign-in method"
                label: qsTrId("settings-accounts-netvfs-la-sign_in_method")
                currentIndex: dialog._authIndex()
                menu: ContextMenu {
                    Repeater {
                        model: dialog.authModes

                        MenuItem {
                            text: NetVfsProviders.text(modelData["label"])
                        }
                    }
                }
                onCurrentIndexChanged: dialog._selectAuthMode(currentIndex)
            }

            PasswordField {
                id: passwordField

                visible: dialog.secretKind === "password" || dialog.secretKind === "token"
                width: parent.width
                label: dialog.secretKind === "token"
                       ? //% "Access token"
                         qsTrId("settings-accounts-netvfs-la-token")
                       : //% "Password"
                         qsTrId("settings-accounts-netvfs-la-password")
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: {
                    if (dialog.canAccept) {
                        dialog.accept()
                    }
                }
            }

            SectionHeader {
                visible: !dialog.credentialsOnly && dialog.offersBackup && dialog.offersFiles
                //% "Use this account for"
                text: qsTrId("settings-accounts-netvfs-he-services")
            }

            TextSwitch {
                id: backupSwitch

                visible: !dialog.credentialsOnly && dialog.offersBackup
                checked: true
                enabled: dialog.backupAllowed
                //% "Backups"
                text: qsTrId("settings-accounts-netvfs-la-service_backup")
                description: dialog.backupAllowed
                             ? //% "The account appears as a backup target in Settings > Backup."
                               qsTrId("settings-accounts-netvfs-la-enable_backups_description")
                             : NetVfsHelpers.serviceRefusalText(dialog.draftParams, "backup")
            }

            TextSwitch {
                id: filesSwitch

                visible: !dialog.credentialsOnly && dialog.offersFiles && dialog.offersBackup && dialog.filesInstalled
                checked: true
                //% "Browsing files"
                text: qsTrId("settings-accounts-netvfs-la-service_files")
                //% "Apps that you allow can browse, open and save files on this server."
                description: qsTrId("settings-accounts-netvfs-la-service_files_description")
            }

            Label {
                visible: !dialog.credentialsOnly && dialog.provider !== "" && dialog.services.length === 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.errorColor
                //% "Choose at least one use for this account."
                text: qsTrId("settings-accounts-netvfs-la-no_service")
            }

            // Service settings (backups folder, start folder) follow their switches.
            Repeater {
                model: dialog.credentialsOnly ? [] : dialog.fields

                TextField {
                    id: serviceField

                    readonly property var field: modelData
                    readonly property string problem: NetVfsProviders.problem(dialog.provider, field, dialog.values,
                                                                              dialog.services)

                    visible: field["service"] !== undefined
                             && NetVfsProviders.isVisible(field, dialog.values, dialog.services)
                    width: column.width
                    label: NetVfsProviders.text(field["label"])
                    placeholderText: label
                    text: dialog._text(field)
                    inputMethodHints: Qt.ImhNoPredictiveText
                    errorHighlight: problem !== ""
                    description: errorHighlight ? problem : NetVfsProviders.text(field["description"] || "")
                    onTextChanged: {
                        if (field["service"] !== undefined) {
                            dialog.setValue(field["key"], text)
                        }
                    }
                    EnterKey.iconSource: "image://theme/icon-m-enter-close"
                    EnterKey.onClicked: focus = false
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
