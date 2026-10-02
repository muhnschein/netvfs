// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Accounts 1.0
import org.netvfs.accounts 1.0

// Creates or updates a netvfs account and its signond identity through
// Sailfish.Accounts (SPEC 6.2, 6.3, 7.3 step 5, 7.5).
//
// create(): account -> settings, display name, backup service enabled ->
// identity via createSignInCredentials("netvfs", "default", ...) without a
// symmetric key (A-3) -> default_credentials_username = user@host (A-2) ->
// done(accountId). Any failure after the account exists removes it again,
// together with an identity already created (U-3).
//
// update(): identity updated (or re-created when it is missing, for example
// after a device restore) -> accepted pin and sign-in method written,
// attention keys cleared (6.4) -> done(accountId). Nothing is removed.
//
// Keep this object alive while busy (parent it to the agent and hold the
// agent's delayDeletion, SPEC U-5).
QtObject {
    id: setup

    readonly property bool busy: _stage !== ""
    property string displayName

    signal done(int accountId)
    signal failed(string text)
    signal saved()

    property string _stage: ""
    property string _provider
    property var _params: ({})
    property string _secret
    property string _backupsPath
    property int _accountId
    property bool _creating
    property Account _account: null

    property AccountManager _manager: AccountManager {
        onAccountCreated: {
            if (setup._stage === "account" && providerName === setup._provider) {
                setup._open(accountId, "configure")
            }
        }
        onAccountCreationFailed: {
            if (setup._stage === "account" && providerName === setup._provider) {
                setup._fail(message)
            }
        }
    }

    property Component _accountComponent: Component {
        Account {
            id: account

            onStatusChanged: setup._statusChanged(account)
            onSignInCredentialsCreated: setup._credentialsStored(account)
            onSignInCredentialsUpdated: setup._credentialsStored(account)
            onSignInError: setup._credentialsFailed(account, message)
        }
    }

    // params: NetVfsHelpers.makeParams() result with the accepted pin;
    // secret: password or "netvfs-key-v1:..." (SshKeyTool.secret()).
    function create(params, secret, backupsPath, name) {
        if (busy) {
            failed(_busyText())
            return
        }
        _creating = true
        // A previous attempt's account (removed, Invalid) must not be touched again.
        _accountId = 0
        if (_account !== null) {
            _account.destroy()
            _account = null
        }
        _provider = params.provider
        _params = params
        _secret = secret
        _backupsPath = backupsPath
        displayName = name.length > 0 ? name : NetVfsHelpers.accountLabel(params.username, params.host)
        _stage = "account"
        if (!_manager.createAccount(_provider)) {
            _fail(_busyText())
        }
    }

    function _busyText() {
        //% "Another account change is still being saved. Try again in a moment."
        return qsTrId("settings-accounts-netvfs-la-setup_busy")
    }

    // secret "" keeps the stored secret (only the settings are updated).
    function update(accountId, params, secret) {
        if (busy) {
            failed(_busyText())
            return
        }
        _creating = false
        _provider = params.provider
        _params = params
        _secret = secret
        _open(accountId, "update")
    }

    // Changes the display name of the account handled last (creation flow,
    // final dialog). Emits saved().
    function rename(name) {
        if (busy || _account === null || name.length === 0 || name === _account.displayName) {
            saved()
            return
        }
        displayName = name
        _stage = "rename"
        _account.displayName = name
        _account.sync()
    }

    function _open(accountId, stage) {
        _accountId = accountId
        _stage = stage
        if (_account !== null) {
            _account.destroy()
        }
        _account = _accountComponent.createObject(setup, { "identifier": accountId })
    }

    function _apply(account, changes) {
        var key
        var global = changes["global"] || {}
        for (key in global) {
            account.setConfigurationValue("", key, global[key])
        }
        var removed = changes["remove"] || []
        for (var i = 0; i < removed.length; ++i) {
            account.removeConfigurationValue("", removed[i])
        }
        var service = changes["service"] || {}
        for (key in service) {
            account.setConfigurationValue(changes["serviceName"], key, service[key])
        }
    }

    function _signInParameters(account) {
        return account.signInParameters(NetVfsHelpers.backupServiceName(_provider), _params.username, _secret)
    }

    function _statusChanged(account) {
        if (_stage === "remove") {
            if (account.status === Account.Invalid || account.status === Account.Synced) {
                _stage = ""
            }
            return
        }
        if (account.status === Account.Invalid || account.status === Account.Error) {
            if (busy) {
                //% "The account could not be saved."
                _fail(qsTrId("settings-accounts-netvfs-la-setup_failed"))
            }
            return
        }
        if (account.status !== Account.Initialized && account.status !== Account.Synced) {
            return
        }
        if (_stage === "configure") {
            _configure(account)
        } else if (_stage === "configured") {
            _stage = "credentials"
            account.createSignInCredentials(NetVfsHelpers.credentialsApplication, NetVfsHelpers.credentialsName,
                                            _signInParameters(account))
        } else if (_stage === "update") {
            _updateCredentials(account)
        } else if (_stage === "recreate") {
            _stage = "credentials"
            account.createSignInCredentials(NetVfsHelpers.credentialsApplication, NetVfsHelpers.credentialsName,
                                            _signInParameters(account))
        } else if (_stage === "finish") {
            _finish()
        } else if (_stage === "rename") {
            _stage = ""
            saved()
        }
    }

    function _configure(account) {
        var changes = NetVfsHelpers.creationSettings(_params, _backupsPath)
        account.displayName = displayName
        _apply(account, changes)
        account.enableWithService(changes["serviceName"])
        account.enabled = true
        _stage = "configured"
        account.sync()
    }

    function _updateCredentials(account) {
        if (_secret.length === 0) {
            _writeSettings(account)
            return
        }
        var app = NetVfsHelpers.credentialsApplication
        var name = NetVfsHelpers.credentialsName
        if (account.hasSignInCredentials(app, name)) {
            _stage = "credentials-update"
            account.updateSignInCredentials(app, name, _signInParameters(account))
        } else {
            _stage = "credentials"
            account.createSignInCredentials(app, name, _signInParameters(account))
        }
    }

    function _credentialsStored(account) {
        if (_stage === "credentials" || _stage === "credentials-update") {
            _writeSettings(account)
        }
    }

    function _credentialsFailed(account, message) {
        if (_stage === "credentials-update") {
            // The identity is gone (device restore): drop the stale reference,
            // then create a new identity once the account has synced.
            _stage = "recreate"
            account.removeSignInCredentials(NetVfsHelpers.credentialsApplication, NetVfsHelpers.credentialsName)
        } else if (_stage === "credentials" || _stage === "recreate") {
            _fail(message)
        }
    }

    function _writeSettings(account) {
        // A-2 after the identity exists: createSignInCredentials() sets the
        // label to the bare login name, which is not unique across servers.
        _apply(account, _creating ? NetVfsHelpers.credentialsLabelSettings(_params)
                                  : NetVfsHelpers.updateSettings(_params))
        _stage = "finish"
        account.sync()
    }

    function _finish() {
        _stage = ""
        _secret = ""
        done(_accountId)
    }

    function _fail(text) {
        _secret = ""
        if (_creating && _stage !== "account" && _account !== null && _accountId > 0) {
            // U-3: no half-created account; remove() also deletes the identity
            // referenced by the segregated_credentials key (SPEC 3.5). The
            // object stays busy (delayDeletion) until the removal is synced.
            _stage = "remove"
            failed(text)
            _account.remove()
            return
        }
        _stage = ""
        failed(text)
    }
}
