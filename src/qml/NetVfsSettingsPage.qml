// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

// Account settings page (SPEC 7.4). A plain page with our own enable switch
// and fields (U-2: not StandardAccountSettingsDisplay). Changes are saved
// when the page is left (U-6), holding the agent's delayDeletion meanwhile
// (U-5).
//
// "Test connection" runs NetVfsProbe.identify() on the stored settings and
// then NetVfsProbe.verifyAccount(): the stored secret is read from signond by
// the C++ core and never reaches QML. A changed server key is reported, never
// accepted here (S-9); the update flow resolves it.
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
    property bool _storedEnabled
    property string _storedName
    // "", "running", "ok" or "failed"
    property string _testState
    property string _testText
    property string _testDetail
    property bool _testOffersUpdate

    readonly property bool _isSftp: provider === "sftp"
    readonly property bool _isSmb: provider === "smb"
    readonly property string _serviceName: NetVfsHelpers.backupServiceName(provider)
    readonly property string _folderProblem: NetVfsInput.backupsPathProblem(provider, folderField.text)
    readonly property var _identity: NetVfsHelpers.identityFromPin(_option("host_key"))

    function _option(key) {
        var options = _params["options"] || {}
        return options[key] !== undefined ? String(options[key]) : ""
    }

    function _load() {
        var values = account.configurationValues("")
        var serviceValues = account.configurationValues(_serviceName)
        var storedPath = serviceValues[NetVfsHelpers.backupsPathKey]
        _params = NetVfsHelpers.paramsFromConfiguration(provider, values)
        _attention = NetVfsHelpers.attentionState(values)
        _storedBackupsPath = storedPath ? String(storedPath) : NetVfsHelpers.defaultBackupsPath
        _storedEnabled = account.enabled && account.isEnabledWithService(_serviceName)
        _storedName = account.displayName
        enableSwitch.checked = _storedEnabled
        descriptionField.text = _storedName
        folderField.text = _storedBackupsPath
        _loaded = true
    }

    // Returns true when a write was started.
    function save(blocking) {
        if (!_loaded || _saving) {
            return false
        }
        var changed = false
        if (enableSwitch.checked !== _storedEnabled) {
            account.enabled = enableSwitch.checked
            if (enableSwitch.checked) {
                account.enableWithService(_serviceName)
            } else {
                account.disableWithService(_serviceName)
            }
            _storedEnabled = enableSwitch.checked
            changed = true
        }
        var name = descriptionField.text.trim()
        if (name.length > 0 && name !== _storedName) {
            account.displayName = name
            _storedName = name
            changed = true
        }
        var path = NetVfsInput.cleanBackupsPath(provider, folderField.text)
        if (_folderProblem === "" && path !== _storedBackupsPath) {
            account.setConfigurationValue(_serviceName, NetVfsHelpers.backupsPathKey, path)
            _storedBackupsPath = path
            changed = true
        }
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
        probe.verifyAccount(agent.accountId, "")
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
                id: enableSwitch

                //% "Back up to this server"
                text: qsTrId("settings-accounts-netvfs-la-enable_backups")
                //% "The account appears as a backup target in Settings > Backup."
                description: qsTrId("settings-accounts-netvfs-la-enable_backups_description")
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

                width: parent.width
                //% "Backups folder"
                label: qsTrId("settings-accounts-netvfs-la-backups_folder")
                inputMethodHints: Qt.ImhNoPredictiveText
                errorHighlight: page._folderProblem !== ""
                description: page._folderProblem
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            SectionHeader {
                //% "Server"
                text: qsTrId("settings-accounts-netvfs-he-server")
            }

            DetailItem {
                //% "Server"
                label: qsTrId("settings-accounts-netvfs-la-server")
                value: page._params["host"] || ""
            }

            DetailItem {
                //% "Port"
                label: qsTrId("settings-accounts-netvfs-la-port")
                value: page._params["port"] > 0 ? String(page._params["port"])
                                                : String(NetVfsInput.defaultPort(page.provider))
            }

            DetailItem {
                visible: page._isSmb
                //% "Share"
                label: qsTrId("settings-accounts-netvfs-la-share")
                value: page._option("share")
            }

            DetailItem {
                //% "User name"
                label: qsTrId("settings-accounts-netvfs-la-user")
                value: page._params["username"] || ""
            }

            DetailItem {
                visible: page._isSmb && page._option("domain") !== ""
                //% "Domain"
                label: qsTrId("settings-accounts-netvfs-la-domain_short")
                value: page._option("domain")
            }

            DetailItem {
                visible: page._isSftp
                //% "Sign-in method"
                label: qsTrId("settings-accounts-netvfs-la-sign_in_method")
                value: NetVfsHelpers.authModeText(page._option("auth_mode"))
            }

            DetailItem {
                // SPEC-smb M-3: "Signed, not encrypted" when encryption is not required
                //% "Connection"
                label: qsTrId("settings-accounts-netvfs-la-connection_security")
                value: NetVfsHelpers.transportSecurityText(page._params)
            }

            SectionHeader {
                visible: page._isSftp && page._identity["fingerprint"] !== undefined
                //% "Server key"
                text: qsTrId("settings-accounts-netvfs-he-server_key")
            }

            Label {
                visible: page._isSftp && page._identity["fingerprint"] !== undefined
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: visible ? page._identity["algorithm"] + "\n" + page._identity["fingerprint"] : ""
            }

            SectionHeader {
                visible: page._isSftp && page._option("public_key") !== ""
                //% "Public key"
                text: qsTrId("settings-accounts-netvfs-he-public_key")
            }

            Label {
                visible: page._isSftp && page._option("public_key") !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * x
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: page._option("public_key")
            }

            Button {
                visible: page._isSftp && page._option("public_key") !== ""
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
