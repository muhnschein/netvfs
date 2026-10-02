// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

// Credentials update flow (SPEC 7.5) shared by sftp-update.qml and
// smb-update.qml. canCancelUpdate is true and nothing is written until the
// new values are verified.
//
//  1. identify() on the stored settings (no credentials sent, C-7).
//  2. A changed (or missing) server key is shown next to the stored one;
//     only an explicit acceptance replaces the pin (S-9).
//  3. server-identity-changed: verify with the stored secret and the
//     accepted pin. auth-failed, credentials missing after a device restore
//     (V7), or a stored secret that no longer works: ask for the secret
//     (SFTP: password, new key or imported key, S-18) and verify it.
//  4. NetVfsAccountSetup.update(): identity, pin, sign-in method, attention
//     keys cleared; then credentialsUpdated() and the end destination.
AccountCredentialsAgent {
    id: root

    property string provider

    property bool _started
    property bool _pageActive
    property var _storedParams: ({ "options": {} })
    property var _params: ({ "options": {} })
    property string _attention
    property string _storedPin
    property string _pin
    property string _backupsPath
    property string _authMode: "password"
    property string _keySource: "generate"
    property string _password
    property bool _usingStoredSecret
    property Item _busyPage
    property Item _credentialsPage
    property Item _keyPage

    property NetVfsProbe _probe: NetVfsProbe {
        onIdentified: root._identified()
        onVerified: root._verified()
        onFailed: root._probeFailed()
    }

    property SshKeyTool _keyTool: SshKeyTool {}

    property NetVfsAccountSetup _setup: NetVfsAccountSetup {
        onDone: root._updated()
        onFailed: root._setupFailed(text)
    }

    property Account _account: Account {
        identifier: root.accountId
        onStatusChanged: root._tryStart()
    }

    canCancelUpdate: true
    // U-5
    delayDeletion: _setup.busy

    function _option(params, key) {
        var options = params["options"] || {}
        return options[key] !== undefined ? String(options[key]) : ""
    }

    function _tryStart() {
        var ready = _account.status === Account.Initialized || _account.status === Account.Synced
        if (_started || !_pageActive || !ready) {
            return
        }
        _started = true
        var values = _account.configurationValues("")
        var serviceValues = _account.configurationValues(NetVfsHelpers.backupServiceName(provider))
        var path = serviceValues[NetVfsHelpers.backupsPathKey]
        _backupsPath = path ? String(path) : NetVfsHelpers.defaultBackupsPath
        _storedParams = NetVfsHelpers.paramsFromConfiguration(provider, values)
        _params = _storedParams
        _attention = NetVfsHelpers.attentionState(values)
        _storedPin = _option(_storedParams, "host_key")
        _authMode = _option(_storedParams, "auth_mode") === "publickey" ? "publickey" : "password"
        _probe.identify(_storedParams)
    }

    function _identified() {
        var status = _probe.identityStatus
        if (status === NetVfsProbe.IdentityChanged || status === NetVfsProbe.IdentityUnknown) {
            pageStack.replace(identityComponent, {
                                  "identity": _probe.serverIdentity,
                                  "storedIdentity": NetVfsHelpers.identityFromPin(_storedPin)
                              })
            return
        }
        _afterIdentity(_storedPin, _busyPage)
    }

    function _afterIdentity(pin, page) {
        _busyPage = page
        _pin = pin
        _params = NetVfsHelpers.withOptions(_storedParams, { "host_key": pin })
        if (_attention === "server-identity-changed") {
            // The secret is probably still valid: verify it with the accepted pin.
            _usingStoredSecret = true
            _busyPage.showBusy(_verifyText())
            _probe.verifyAccount(root.accountId, pin)
        } else {
            _askCredentials()
        }
    }

    function _askCredentials() {
        _usingStoredSecret = false
        pageStack.replace(credentialsComponent)
    }

    function _collectCredentials(dialog) {
        if (dialog.authMode !== _authMode || dialog.keySource !== _keySource) {
            _keyTool.clear()
        }
        _authMode = dialog.authMode
        _keySource = dialog.keySource
        _password = dialog.password
        var options = { "host_key": _pin, "public_key": "" }
        if (provider === "sftp") {
            options["auth_mode"] = _authMode
        }
        _params = NetVfsHelpers.withOptions(_storedParams, options)
    }

    function _secret() {
        return _authMode === "publickey" ? _keyTool.secret() : _password
    }

    function _startVerify(page) {
        _busyPage = page
        _usingStoredSecret = false
        if (_authMode === "publickey") {
            _params = NetVfsHelpers.withOptions(_params, { "public_key": _keyTool.publicKey })
        }
        _probe.verify(_params, { "username": _params["username"], "secret": _secret() }, _backupsPath)
    }

    function _verified() {
        //% "Saving the sign-in details"
        _busyPage.showBusy(qsTrId("settings-accounts-netvfs-la-saving_credentials"))
        _setup.update(root.accountId, _params, _usingStoredSecret ? "" : _secret())
    }

    function _updated() {
        _password = ""
        _keyTool.clear()
        root.credentialsUpdated(root.accountId)
        root.goToEndDestination()
    }

    function _setupFailed(text) {
        root.credentialsUpdateError(text)
        //% "The sign-in details could not be saved"
        _busyPage.showError(qsTrId("settings-accounts-netvfs-he-update_failed"), text, "")
    }

    function _probeFailed() {
        if (_usingStoredSecret && _probe.error === NetVfsProbe.AuthFailed) {
            _askCredentials()
            return
        }
        //% "Checking the server failed"
        _busyPage.showError(qsTrId("settings-accounts-netvfs-he-check_failed"), _probe.errorText,
                            _probe.errorDetail)
    }

    function _verifyText() {
        //% "Signing in and checking the backups folder"
        return qsTrId("settings-accounts-netvfs-la-verifying")
    }

    // U-4: back to where the input can be changed.
    function _goBack() {
        _probe.cancel()
        if (_keyPage !== null && _authMode === "publickey" && _probe.error === NetVfsProbe.AuthFailed) {
            pageStack.pop(_keyPage)
        } else if (_credentialsPage !== null) {
            pageStack.pop(_credentialsPage)
        } else {
            pageStack.pop()
        }
    }

    initialPage: ProbeBusyPage {
        id: startPage

        //% "Contacting the server"
        busyDescription: qsTrId("settings-accounts-netvfs-la-identifying")
        onPageActivated: {
            root._busyPage = startPage
            root._pageActive = true
            root._tryStart()
        }
        onEditRequested: root._goBack()
    }

    Component {
        id: identityComponent

        ServerIdentityDialog {
            acceptDestination: checkComponent
            acceptDestinationAction: PageStackAction.Push
            onAccepted: root._pin = identity.pin
        }
    }

    Component {
        id: checkComponent

        ProbeBusyPage {
            id: checkPage

            busyDescription: root._verifyText()
            onPageActivated: root._afterIdentity(root._pin, checkPage)
            onEditRequested: root._goBack()
        }
    }

    Component {
        id: credentialsComponent

        ConnectionDialog {
            id: credentialsDialog

            provider: root.provider
            credentialsOnly: true
            initialAuthMode: root._authMode
            acceptDestination: authMode === "publickey" ? keyComponent : verifyComponent
            acceptDestinationAction: PageStackAction.Push
            onAccepted: root._collectCredentials(credentialsDialog)
            onStatusChanged: {
                if (status === PageStatus.Active) {
                    root._credentialsPage = credentialsDialog
                }
            }
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
        }
    }
}
