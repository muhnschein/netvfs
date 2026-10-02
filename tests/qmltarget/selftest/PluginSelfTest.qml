// SPDX-License-Identifier: LGPL-2.1-or-later
// Instantiated by run-in-sdk.sh on the target's Qt 5.6 engine: the C++ types'
// scoped enums (enum class + Q_ENUM) and both singletons must be usable from
// QML exactly as the pages use them. A failed check throws, which qmlcheck
// reports as a warning in this file and so as a failure.
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
        check(NetVfsInput.backupsPathProblem("smb", "a:b") !== "", "NetVfsInput M-9")
        check(NetVfsHelpers.credentialsApplication === "netvfs", "NetVfsHelpers")
        check(NetVfsProbe.IdentityTrusted === 5, "IdentityStatus.IdentityTrusted")
        // SPEC-v2 XA-5: run-in-sdk.sh points NETVFS_PROVIDERS_DIR at accounts/descriptors.
        check(NetVfsProviders.providers().length === 4, "NetVfsProviders.providers")
        check(NetVfsProviders.descriptor("smb").fields.length > 5, "NetVfsProviders.descriptor")
        check(NetVfsProviders.offersService("webdav", "files") && !NetVfsProviders.offersService("webdav", "backup"),
              "NetVfsProviders.offersService")
        check(NetVfsProviders.secretKind("smb", { "security_profile": "guest" }) === "none", "secretKind")
        check(!NetVfsHelpers.serviceAllowed(NetVfsHelpers.makeParams("smb", "nas", "", "",
                                                                     { "security_profile": "guest", "share": "s" }),
                                            "backup"), "serviceAllowed")
        check(consents.count >= 0 && consents.consent("lautta") !== "", "NetVfsConsentModel")
    }
}
