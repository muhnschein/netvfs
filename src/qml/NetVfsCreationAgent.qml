// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

// Creation flow (SPEC 7.3) shared by sftp.qml and smb.qml:
// input -> identify (no credentials, C-7) -> confirm server identity (SFTP,
// S-7/S-8) -> [SSH key page, S-16] -> verify -> create (U-3) -> final dialog.
// Uses only the AccountCreationAgent members listed in SPEC 7.1 (R1) and no
// OnlineSync* component or AccountFactory (U-1).
AccountCreationAgent {
    id: root

    property string provider

    property var _params: ({})
    property string _authMode: "password"
    property string _keySource: "generate"
    property string _password
    property string _backupsPath
    property Item _busyPage
    property Item _keyPage
    property bool _verifying

    // Parented to the agent so they outlive the pages (U-5).
    property NetVfsProbe _probe: NetVfsProbe {
        onIdentified: root._identified()
        onVerified: root._verified()
        onFailed: root._probeFailed()
    }

    property SshKeyTool _keyTool: SshKeyTool {}

    property NetVfsAccountSetup _setup: NetVfsAccountSetup {
        onDone: root._created(accountId)
        onFailed: root._setupFailed(text)
    }

    // U-5: hold the agent while the account is written.
    delayDeletion: _setup.busy

    function _collectInput() {
        if (connectionDialog.keySource !== _keySource || connectionDialog.authMode !== _authMode) {
            _keyTool.clear()
        }
        _authMode = connectionDialog.authMode
        _keySource = connectionDialog.keySource
        _password = connectionDialog.password
        _backupsPath = connectionDialog.backupsPath
        _params = connectionDialog.connectionParams("")
    }

    function _startIdentify(page) {
        _busyPage = page
        _verifying = false
        _probe.identify(_params)
    }

    // A result is only acted on while its busy page is still shown.
    function _onBusyPage() {
        return _busyPage !== null && pageStack.currentPage === _busyPage
    }

    function _identified() {
        if (!_onBusyPage()) {
            return
        }
        if (_probe.identityStatus === NetVfsProbe.IdentityUnknown) {
            pageStack.replace(identityComponent, { "identity": _probe.serverIdentity })
        } else if (_probe.identityStatus === NetVfsProbe.NoIdentity) {
            // SMB has no server identity to confirm (SPEC-smb 3).
            _busyPage.showBusy(_verifyText())
            _startVerify(_busyPage)
        } else {
            //% "The server's identity could not be checked."
            _busyPage.showError(_errorHeading(), qsTrId("settings-accounts-netvfs-la-identity_unexpected"), "")
        }
    }

    function _identityAccepted(pin) {
        _params = connectionDialog.connectionParams(pin)
    }

    function _startVerify(page) {
        _busyPage = page
        _verifying = true
        if (_authMode === "publickey") {
            // Stored with the account for display (SPEC-sftp 2).
            _params = NetVfsHelpers.withOptions(_params, { "public_key": _keyTool.publicKey })
        }
        var secret = _authMode === "publickey" ? _keyTool.secret() : _password
        _probe.verify(_params, { "username": _params.username, "secret": secret }, _backupsPath)
    }

    function _verified() {
        if (!_onBusyPage()) {
            return
        }
        //% "Adding the account"
        _busyPage.showBusy(qsTrId("settings-accounts-netvfs-la-creating_account"))
        var secret = _authMode === "publickey" ? _keyTool.secret() : _password
        _setup.create(_params, secret, _backupsPath, "")
    }

    function _created(accountId) {
        _password = ""
        connectionDialog.clearPassword()
        _keyTool.clear()
        root.accountCreated(accountId)
        pageStack.replace(finishComponent, { "freeBytes": _probe.freeBytes })
    }

    function _setupFailed(text) {
        root.accountCreationError(text)
        //% "The account could not be added"
        _busyPage.showError(qsTrId("settings-accounts-netvfs-he-setup_failed"), text, "")
    }

    function _probeFailed() {
        if (!_onBusyPage()) {
            return
        }
        _busyPage.showError(_errorHeading(), _probe.errorText, _probe.errorDetail)
    }

    function _errorHeading() {
        return _verifying
                ? //% "Signing in failed"
                  qsTrId("settings-accounts-netvfs-he-verify_failed")
                : //% "Connecting failed"
                  qsTrId("settings-accounts-netvfs-he-identify_failed")
    }

    function _verifyText() {
        //% "Signing in and checking the backups folder"
        return qsTrId("settings-accounts-netvfs-la-verifying")
    }

    // U-4: back to the input, or to the key page when the key was refused.
    function _goBack() {
        _probe.cancel()
        if (_verifying && _keyPage !== null && _probe.error === NetVfsProbe.AuthFailed) {
            pageStack.pop(_keyPage)
        } else {
            pageStack.pop(connectionDialog)
        }
    }

    initialPage: ConnectionDialog {
        id: connectionDialog

        provider: root.provider
        acceptDestination: identifyComponent
        acceptDestinationAction: PageStackAction.Push
        onAccepted: root._collectInput()
    }

    Component {
        id: identifyComponent

        ProbeBusyPage {
            id: identifyPage

            //% "Contacting the server"
            busyDescription: qsTrId("settings-accounts-netvfs-la-identifying")
            onPageActivated: root._startIdentify(identifyPage)
            onEditRequested: root._goBack()
            onLeft: root._probe.cancel()
        }
    }

    Component {
        id: identityComponent

        ServerIdentityDialog {
            acceptDestination: root._authMode === "publickey" ? keyComponent : verifyComponent
            acceptDestinationAction: PageStackAction.Push
            onAccepted: root._identityAccepted(identity.pin)
        }
    }

    Component {
        id: keyComponent

        SshKeyPage {
            id: keyPage

            keyTool: root._keyTool
            keySource: root._keySource
            params: root._params
            acceptDestination: verifyComponent
            acceptDestinationAction: PageStackAction.Push
            onStatusChanged: {
                if (status === PageStatus.Active) {
                    root._keyPage = keyPage
                }
            }
        }
    }

    Component {
        id: verifyComponent

        ProbeBusyPage {
            id: verifyPage

            busyDescription: root._verifyText()
            onPageActivated: root._startVerify(verifyPage)
            onEditRequested: root._goBack()
            onLeft: root._probe.cancel()
        }
    }

    Component {
        id: finishComponent

        // SPEC 7.3 step 6: editable description; accept goes to the end destination.
        Dialog {
            id: finishDialog

            property real freeBytes: -1

            backNavigation: false
            acceptDestination: root.endDestination
            acceptDestinationAction: root.endDestinationAction
            acceptDestinationProperties: root.endDestinationProperties
            acceptDestinationReplaceTarget: root.endDestinationReplaceTarget
            onAccepted: root._setup.rename(descriptionField.text.trim())

            SilicaFlickable {
                anchors.fill: parent
                contentHeight: finishColumn.height + Theme.paddingLarge

                Column {
                    id: finishColumn

                    width: parent.width
                    spacing: Theme.paddingLarge

                    DialogHeader {}

                    Label {
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * x
                        wrapMode: Text.Wrap
                        color: Theme.highlightColor
                        //% "The account was added. Backups to this server can now be made in Settings > Backup."
                        text: qsTrId("settings-accounts-netvfs-la-account_added")
                    }

                    Label {
                        visible: finishDialog.freeBytes >= 0
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * x
                        wrapMode: Text.Wrap
                        color: Theme.secondaryHighlightColor
                        //% "Free space on the server: %1"
                        text: qsTrId("settings-accounts-netvfs-la-free_space").arg(Format.formatFileSize(finishDialog.freeBytes))
                    }

                    TextField {
                        id: descriptionField

                        width: parent.width
                        //% "Description"
                        label: qsTrId("settings-accounts-netvfs-la-description")
                        text: root._setup.displayName
                        EnterKey.iconSource: "image://theme/icon-m-enter-close"
                        EnterKey.onClicked: focus = false
                    }
                }
            }
        }
    }
}
