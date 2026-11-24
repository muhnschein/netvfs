// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Accounts 1.0
import org.netvfs.accounts 1.0

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
    property var _services: ({})
    property string _signInService
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

    function create(params, secret, services, name) {
        if (busy) {
            failed(_busyText())
            return
        }
        _creating = true
        _accountId = 0
        if (_account !== null) {
            _account.destroy()
            _account = null
        }
        _provider = params.provider
        _params = params
        _secret = secret
        _services = services
        _signInService = NetVfsHelpers.creationSettings(params, services)["signInService"]
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

    function update(accountId, params, secret) {
        if (busy) {
            failed(_busyText())
            return
        }
        _creating = false
        _provider = params.provider
        _params = params
        _secret = secret
        var backupService = NetVfsHelpers.backupServiceName(_provider)
        _signInService = NetVfsProviders.offersService(_provider, "backup") && NetVfsHelpers.isServiceInstalled(backupService)
                ? backupService : NetVfsHelpers.filesServiceName(_provider)
        _open(accountId, "update")
    }

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
        var services = changes["services"] || {}
        for (var name in services) {
            var values = services[name]
            for (key in values) {
                account.setConfigurationValue(name, key, values[key])
            }
        }
    }

    function _signInParameters(account) {
        return account.signInParameters(_signInService, _params.username, _secret)
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
        var changes = NetVfsHelpers.creationSettings(_params, _services)
        account.displayName = displayName
        _apply(account, changes)
        var enable = changes["enable"] || []
        for (var i = 0; i < enable.length; ++i) {
            account.enableWithService(enable[i])
        }
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
            _stage = "recreate"
            account.removeSignInCredentials(NetVfsHelpers.credentialsApplication, NetVfsHelpers.credentialsName)
        } else if (_stage === "credentials" || _stage === "recreate") {
            _fail(message)
        }
    }

    function _writeSettings(account) {
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
            _stage = "remove"
            failed(text)
            _account.remove()
            return
        }
        _stage = ""
        failed(text)
    }
}
