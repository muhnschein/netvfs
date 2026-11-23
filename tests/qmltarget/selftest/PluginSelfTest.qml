// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import org.netvfs.accounts 1.0

Item {
    NetVfsProbe {
        id: probe
    }

    SshKeyTool {
        id: keys
    }

    NetVfsConsentModel {
        id: consents
    }

    NetVfsAccessModel {
        id: access

        consumerId: "lautta"
        autoSave: false
    }

    function check(ok, what) {
        if (!ok) {
            throw new Error("plugin self-test failed: " + what)
        }
    }

    Component.onCompleted: {
        check(NetVfsProbe.Idle === 0 && probe.state === NetVfsProbe.Idle, "NetVfsProbe.State")
        check(NetVfsProbe.Verified === 4 && NetVfsProbe.Failed === 5, "NetVfsProbe.State values")
        check(NetVfsProbe.AuthFailed === 6 && probe.error === NetVfsProbe.NoError, "NetVfsProbe.ErrorCode")
        check(NetVfsProbe.ServerIdentityChanged === 5, "NetVfsProbe.ErrorCode values")
        check(probe.identityStatus === NetVfsProbe.IdentityNotChecked, "NetVfsProbe.IdentityStatus")
        check(NetVfsProbe.IdentityChanged === 4 && NetVfsProbe.NoIdentity === 1, "IdentityStatus values")
        check(!probe.busy, "NetVfsProbe.busy")
        check(keys.state === SshKeyTool.Empty && SshKeyTool.Ready === 3, "SshKeyTool.State")
        check(keys.installState === SshKeyTool.InstallIdle && SshKeyTool.InstallFailed === 3,
              "SshKeyTool.InstallState")
        check(NetVfsInput.defaultPort("sftp") === 22 && NetVfsInput.portValue("2222") === 2222, "NetVfsInput")
        check(NetVfsInput.backupsPathProblem("smb", "a:b") !== "", "NetVfsInput Windows-invalid name")
        check(NetVfsHelpers.credentialsApplication === "netvfs", "NetVfsHelpers")
        check(NetVfsProviders.providers().length === 4, "NetVfsProviders.providers")
        check(NetVfsProviders.offersService("webdav", "backup") && NetVfsProviders.offersService("ftps", "backup"),
              "NetVfsProviders.offersService webdav ftps")
        check(NetVfsProviders.descriptor("smb").fields.length > 5, "NetVfsProviders.descriptor")
        check(NetVfsProviders.offersService("smb", "files") && !NetVfsProviders.offersService("local", "backup"),
              "NetVfsProviders.offersService")
        check(NetVfsProviders.secretKind("smb", { "security_profile": "guest" }) === "none", "secretKind")
        check(!NetVfsHelpers.serviceAllowed(NetVfsHelpers.makeParams("smb", "nas", "", "",
                                                                     { "security_profile": "guest", "share": "s" }),
                                            "backup"), "serviceAllowed")
        check(consents.count >= 0 && typeof consents.firstPending() === "string", "NetVfsConsentModel")
        check(access.count >= 0 && access.autoSave === false && access.newAccounts !== "", "NetVfsAccessModel")
    }
}
