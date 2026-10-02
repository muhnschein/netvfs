// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

// Account settings page (SPEC 7.4). A plain page with our own switches and
// fields (U-2: not StandardAccountSettingsDisplay). Changes are saved when
// the page is left (U-6), holding the agent's delayDeletion meanwhile (U-5).
//
// One switch per service the provider offers (SPEC-v2 XA-1, amends 7.4 "only
// one service"): backups (<p>-backup, where the provider offers it and the
// settings allow it, XA-4) and browsing files (<p>-files, when the
// netvfs-files-services package is installed). The account is enabled
// while any of its services is.
//
// "Test connection" runs NetVfsProbe.identify() on the stored settings and
// then NetVfsProbe.verifyAccount() for backups when they are on, else for
// files (which writes nothing): the stored secret is read from signond by
// the C++ core and never reaches QML. A changed server identity is
// reported, never accepted here (S-9); the update flow resolves it.
//
// The pull-down menu also opens "Apps using network locations"
// (NetVfsConsentPage, SPEC-v2 XB-6).
Page {
    id: page

    // The AccountSettingsAgent (accountId, accountsHeaderText, delayDeletion,
    // accountDeletionRequested(); SPEC 7.1)
    property QtObject agent
    property string provider

    property bool _loaded
    property bool _saving
    property bool _testAfterSave
    property var _params: ({ "options": {} })
    property string _attention
    property string _storedBackupsPath
    property string _storedFilesRoot
    property bool _storedBackup
    property bool _storedFiles
    property string _storedName
    // "", "running", "ok" or "failed"
    property string _testState
    property string _testText
    property string _testDetail
    property bool _testOffersUpdate

    readonly property string _backupService: NetVfsHelpers.backupServiceName(provider)
    readonly property string _filesService: NetVfsHelpers.filesServiceName(provider)
    readonly property bool _offersBackup: NetVfsProviders.offersService(provider, "backup")
    readonly property bool _offersFiles: NetVfsProviders.offersService(provider, "files")
                                         && NetVfsHelpers.isServiceInstalled(_filesService)
    readonly property bool _backupAllowed: NetVfsHelpers.serviceAllowed(_params, "backup")
    readonly property bool _multipleAuthModes: (NetVfsProviders.descriptor(provider)["authModes"] || []).length > 1
    readonly property string _folderProblem: backupSwitch.checked
                                             ? NetVfsInput.backupsPathProblem(provider, folderField.text) : ""
    readonly property string _rootProblem: filesSwitch.checked && filesRootField.text.trim() !== ""
                                           ? NetVfsInput.backupsPathProblem(provider, filesRootField.text) : ""
    readonly property var _identity: NetVfsHelpers.identityFromPin(_option("host_key"))
    readonly property var _details: NetVfsProviders.details(provider, _params)

    function _option(key) {
        var options = _params["options"] || {}
        return options[key] !== undefined ? String(options[key]) : ""
    }

    function _load() {
        var values = account.configurationValues("")
        var backupValues = account.configurationValues(_backupService)
        var filesValues = account.configurationValues(_filesService)
        var storedPath = backupValues[NetVfsHelpers.backupsPathKey]
        var storedRoot = filesValues[NetVfsHelpers.filesRootKey]
        _params = NetVfsHelpers.paramsFromConfiguration(provider, values)
        _attention = NetVfsHelpers.attentionState(values)
        _storedBackupsPath = storedPath ? String(storedPath) : NetVfsHelpers.defaultBackupsPath
        _storedFilesRoot = storedRoot ? String(storedRoot) : ""
        _storedBackup = _offersBackup && account.enabled && account.isEnabledWithService(_backupService)
        _storedFiles = _offersFiles && account.enabled && account.isEnabledWithService(_filesService)
        _storedName = account.displayName
        backupSwitch.checked = _storedBackup
        filesSwitch.checked = _storedFiles
        descriptionField.text = _storedName
        folderField.text = _storedBackupsPath
        filesRootField.text = _storedFilesRoot
        _loaded = true
    }

    function _saveService(name, on) {
        if (on) {
            account.enableWithService(name)
        } else {
            account.disableWithService(name)
        }
    }

    function _saveServices() {
        var backup = backupSwitch.checked && _backupAllowed
        var files = filesSwitch.checked
        if (backup === _storedBackup && files === _storedFiles) {
            return false
        }
        account.enabled = backup || files
        if (_offersBackup && backup !== _storedBackup) {
            _saveService(_backupService, backup)
        }
        if (_offersFiles && files !== _storedFiles) {
            _saveService(_filesService, files)
        }
        _storedBackup = backup
        _storedFiles = files
        return true
    }

    function _saveFolders() {
        var changed = false
        var path = NetVfsInput.cleanBackupsPath(provider, folderField.text)
        if (_offersBackup && _folderProblem === "" && folderField.text.trim() !== "" && path !== _storedBackupsPath) {
            account.setConfigurationValue(_backupService, NetVfsHelpers.backupsPathKey, path)
            _storedBackupsPath = path
            changed = true
        }
        var root = NetVfsInput.cleanBackupsPath(provider, filesRootField.text)
        if (_offersFiles && _rootProblem === "" && root !== _storedFilesRoot) {
            account.setConfigurationValue(_filesService, NetVfsHelpers.filesRootKey, root)
            _storedFilesRoot = root
            changed = true
        }
        return changed
    }

    // Returns true when a write was started.
    function save(blocking) {
        if (!_loaded || _saving) {
            return false
        }
        var changed = _saveServices()
        var name = descriptionField.text.trim()
        if (name.length > 0 && name !== _storedName) {
            account.displayName = name
            _storedName = name
            changed = true
        }
        changed = _saveFolders() || changed
        if (!changed) {
            return false
        }
        if (blocking) {
            account.blockingSync()
            return false
        }
        _saving = true
        agent.delayDeletion = true
        account.sync()
        return true
    }

    function _accountStatusChanged() {
        if (account.status === Account.Initialized && !_loaded) {
            _load()
            return
        }
        var finished = account.status === Account.Synced || account.status === Account.Error
                || account.status === Account.Invalid
        if (_saving && finished) {
            _saving = false
            agent.delayDeletion = false
            if (_testAfterSave) {
                _testAfterSave = false
                _runTest()
            }
        }
    }

    function _updateCredentials() {
        save(false)
        credentialsUpdater.replaceWithCredentialsUpdatePage(agent.accountId)
    }

    function _testService() {
        return backupSwitch.checked && _offersBackup && _backupAllowed ? "backup" : "files"
    }

    function _startTest() {
        _testState = "running"
        _testText = ""
        _testDetail = ""
        _testOffersUpdate = false
        if (save(false)) {
            _testAfterSave = true
        } else {
            _runTest()
        }
    }

    function _runTest() {
        probe.identify(_params)
    }

    function _identifiedForTest() {
        if (probe.identityStatus === NetVfsProbe.IdentityChanged) {
            //% "The server presented a different key than the one stored for this account. Use Update sign-in details to check it."
            _finishTest("failed", qsTrId("settings-accounts-netvfs-la-test_key_changed"), "", true)
            return
        }
        if (probe.identityStatus === NetVfsProbe.IdentityUnknown) {
            //% "The server's identity has not been confirmed for this account. Use Update sign-in details to check it."
            _finishTest("failed", qsTrId("settings-accounts-netvfs-la-test_identity_unknown"), "", true)
            return
        }
        probe.verifyAccount(agent.accountId, {}, _testService())
    }

    function _verifiedForTest() {
        var text = probe.freeBytes >= 0
                ? //% "The connection works. Free space on the server: %1"
                  qsTrId("settings-accounts-netvfs-la-test_ok_space").arg(Format.formatFileSize(probe.freeBytes))
                : //% "The connection works."
                  qsTrId("settings-accounts-netvfs-la-test_ok")
        _finishTest("ok", text, "", false)
    }

    function _testFailed() {
        var offerUpdate = probe.error === NetVfsProbe.AuthFailed || probe.error === NetVfsProbe.ServerIdentityChanged
        _finishTest("failed", probe.errorText, probe.errorDetail, offerUpdate)
    }

    function _finishTest(state, text, detail, offerUpdate) {
        _testState = state
        _testText = text
        _testDetail = detail
        _testOffersUpdate = offerUpdate
    }

    // U-6
    onPageContainerChanged: {
        if (pageContainer === null) {
            probe.cancel()
            save(false)
        }
    }

    Component.onDestruction: {
        if (status === PageStatus.Active) {
            save(true)
        }
    }

    Account {
        id: account

        identifier: page.agent ? page.agent.accountId : 0
        onStatusChanged: page._accountStatusChanged()
    }

    NetVfsProbe {
        id: probe

        onIdentified: page._identifiedForTest()
        onVerified: page._verifiedForTest()
        onFailed: page._testFailed()
    }

    AccountCredentialsUpdater {
        id: credentialsUpdater
    }

    Component {
        id: consentComponent

        NetVfsConsentPage {}
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        StandardAccountSettingsPullDownMenu {
            allowSync: false
            allowCredentialsUpdate: true
            allowDelete: true
            onCredentialsUpdateRequested: page._updateCredentials()
            onAccountDeletionRequested: {
                page.agent.accountDeletionRequested()
                pageStack.pop()
            }

            MenuItem {
                //% "Apps using network locations"
                text: qsTrId("settings-accounts-netvfs-me-consent_page")
                onClicked: pageStack.push(consentComponent)
            }
        }

        Column {
            id: column

            width: parent.width

            PageHeader {
                title: page.agent ? page.agent.accountsHeaderText : ""
            }

            Column {
                // Attention banner (SPEC 6.4, 7.4)
                visible: page._attention !== ""
                width: parent.width
                spacing: Theme.paddingMedium

                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * x
                    wrapMode: Text.Wrap
                    color: Theme.errorColor
                    text: NetVfsHelpers.attentionText(page._attention)
                }

                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    //% "Update sign-in details"
                    text: qsTrId("settings-accounts-netvfs-bt-update_credentials")
                    onClicked: page._updateCredentials()
                }

                Item {
                    width: 1
                    height: Theme.paddingMedium
                }
            }

            TextSwitch {
                id: backupSwitch

                visible: page._offersBackup
                enabled: page._backupAllowed
                //% "Back up to this server"
                text: qsTrId("settings-accounts-netvfs-la-enable_backups")
                description: page._backupAllowed
                             ? //% "The account appears as a backup target in Settings > Backup."
                               qsTrId("settings-accounts-netvfs-la-enable_backups_description")
                             : NetVfsHelpers.serviceRefusalText(page._params, "backup")
            }

            TextSwitch {
                id: filesSwitch

                visible: page._offersFiles
                //% "Browse files"
                text: qsTrId("settings-accounts-netvfs-la-enable_files")
                //% "Apps that you allow can browse, open and save files on this server."
                description: qsTrId("settings-accounts-netvfs-la-service_files_description")
            }

            TextField {
                id: descriptionField

                width: parent.width
                //% "Description"
                label: qsTrId("settings-accounts-netvfs-la-description")
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            TextField {
                id: folderField

                visible: page._offersBackup && backupSwitch.checked
                width: parent.width
                //% "Backups folder"
                label: qsTrId("settings-accounts-netvfs-la-backups_folder")
                inputMethodHints: Qt.ImhNoPredictiveText
                errorHighlight: page._folderProblem !== ""
                description: page._folderProblem
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            TextField {
                id: filesRootField

                visible: page._offersFiles && filesSwitch.checked
                width: parent.width
                //% "Start folder"
                label: qsTrId("settings-accounts-netvfs-la-files_root")
                //% "Default folder"
                placeholderText: qsTrId("settings-accounts-netvfs-ph-files_root")
                inputMethodHints: Qt.ImhNoPredictiveText
                errorHighlight: page._rootProblem !== ""
                description: page._rootProblem
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            SectionHeader {
                //% "Server"
                text: qsTrId("settings-accounts-netvfs-he-server")
            }

            Repeater {
                // Fields of the provider descriptor (SPEC-v2 XA-5), read-only.
                model: page._details

                DetailItem {
                    label: modelData["label"]
                    value: modelData["value"]
                }
            }

            DetailItem {
                visible: page._multipleAuthModes
                //% "Sign-in method"
                label: qsTrId("settings-accounts-netvfs-la-sign_in_method")
                value: NetVfsHelpers.authModeText(page._option("auth_mode"))
            }

            SectionHeader {
                visible: page._identity["fingerprint"] !== undefined
                text: page._identity["kind"] === "tls"
                      ? //% "Server certificate"
                        qsTrId("settings-accounts-netvfs-he-server_certificate")
                      : //% "Server key"
                        qsTrId("settings-accounts-netvfs-he-server_key")
            }

            Label {
                visible: page._identity["fingerprint"] !== undefined
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: visible ? page._identity["algorithm"] + "\n" + page._identity["fingerprint"] : ""
            }

            SectionHeader {
                visible: page._option("public_key") !== ""
                //% "Public key"
                text: qsTrId("settings-accounts-netvfs-he-public_key")
            }

            Label {
                visible: page._option("public_key") !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: page._option("public_key")
            }

            Button {
                visible: page._option("public_key") !== ""
                anchors.horizontalCenter: parent.horizontalCenter
                //% "Copy to clipboard"
                text: qsTrId("settings-accounts-netvfs-bt-copy_public_key")
                onClicked: Clipboard.text = page._option("public_key")
            }

            SectionHeader {
                //% "Connection test"
                text: qsTrId("settings-accounts-netvfs-he-test")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: page._loaded && page._testState !== "running" && page._folderProblem === ""
                         && page._rootProblem === ""
                //% "Test connection"
                text: qsTrId("settings-accounts-netvfs-bt-test_connection")
                onClicked: page._startTest()
            }

            Row {
                visible: page._testState === "running"
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
                    //% "Testing the connection"
                    text: qsTrId("settings-accounts-netvfs-la-testing")
                }
            }

            Label {
                visible: page._testState === "ok" || page._testState === "failed"
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.Wrap
                color: page._testState === "ok" ? Theme.highlightColor : Theme.errorColor
                text: page._testText + (page._testDetail !== "" ? "\n" + page._testDetail : "")
            }

            Button {
                visible: page._testOffersUpdate
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTrId("settings-accounts-netvfs-bt-update_credentials")
                onClicked: page._updateCredentials()
            }
        }

        VerticalScrollDecorator {}
    }
}
