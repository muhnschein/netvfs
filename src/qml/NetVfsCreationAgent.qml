// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

AccountCreationAgent {
    id: root

    property string provider

    property var _params: ({})
    property string _authMode: "password"
    property string _keySource: "generate"
    property string _password
    property string _secretKind: "password"
    property string _backupsPath
    property string _filesRoot
    property bool _backup
    property bool _files
    property Item _busyPage
    property Item _keyPage
    property bool _verifying

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

    delayDeletion: _setup.busy

    function _collectInput() {
        if (connectionDialog.keySource !== _keySource || connectionDialog.authMode !== _authMode) {
            _keyTool.clear()
        }
        _authMode = connectionDialog.authMode
        _keySource = connectionDialog.keySource
        _secretKind = connectionDialog.secretKind
        _password = connectionDialog.password
        _backupsPath = connectionDialog.backupsPath
        _filesRoot = connectionDialog.filesRoot
        _backup = connectionDialog.backupSelected
        _files = connectionDialog.filesSelected
        _params = connectionDialog.connectionParams({})
    }

    function _secret() {
        if (_secretKind === "key") {
            return _keyTool.secret()
        }
        return _secretKind === "none" ? "" : _password
    }

    function _startIdentify(page) {
        _busyPage = page
        _verifying = false
        _probe.identify(_params)
    }

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
            _busyPage.showBusy(_verifyText())
            _startVerify(_busyPage)
        } else {
            //% "The server's identity could not be checked."
            _busyPage.showError(_errorHeading(), qsTrId("settings-accounts-netvfs-la-identity_unexpected"), "")
        }
    }

    function _identityAccepted(pinOptions) {
        _params = connectionDialog.connectionParams(pinOptions)
    }

    function _startVerify(page) {
        _busyPage = page
        _verifying = true
        if (_authMode === "publickey") {
            _params = NetVfsHelpers.withOptions(_params, { "public_key": _keyTool.publicKey })
        }
        if (_backup) {
            _probe.verify(_params, { "username": _params.username, "secret": _secret() }, _backupsPath, "backup")
        } else {
            _probe.verify(_params, { "username": _params.username, "secret": _secret() }, _filesRoot, "files")
        }
    }

    function _verified() {
        if (!_onBusyPage()) {
            return
        }
        //% "Adding the account"
        _busyPage.showBusy(qsTrId("settings-accounts-netvfs-la-creating_account"))
        _setup.create(_params, _secret(), {
                          "backup": _backup,
                          "files": _files,
                          "backupsPath": _backupsPath,
                          "filesRoot": _filesRoot
                      }, "")
    }

    function _created(accountId) {
        _password = ""
        connectionDialog.clearPassword()
        _keyTool.clear()
        root.accountCreated(accountId)
        pageStack.replace(finishComponent, { "freeBytes": _probe.freeBytes, "backup": _backup })
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
        if (_backup) {
            //% "Signing in and checking the backups folder"
            return qsTrId("settings-accounts-netvfs-la-verifying")
        }
        //% "Signing in and checking the start folder"
        return qsTrId("settings-accounts-netvfs-la-verifying_files")
    }

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
            onAccepted: root._identityAccepted(identity.pinOptions)
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

        Dialog {
            id: finishDialog

            property real freeBytes: -1
            property bool backup

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
                        text: finishDialog.backup
                              ? //% "The account was added. Backups to this server can now be made in Settings > Backup."
                                qsTrId("settings-accounts-netvfs-la-account_added")
                              : //% "The account was added. Apps that you allow can now use files on this server."
                                qsTrId("settings-accounts-netvfs-la-account_added_files")
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
