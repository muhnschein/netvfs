// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// What one app may do on each account (NetVfsConsentPage). Each change is stored at once; a running
// bridge applies it, and closes the app's connections when it allows less.
Page {
    id: page

    property alias consumerId: access.consumerId
    // Consent file; empty: the default (~/.config/netvfs/bridge.conf).
    property alias storePath: access.storePath

    NetVfsAccessModel {
        id: access
    }

    onStatusChanged: {
        if (status === PageStatus.Activating) {
            access.reload()
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        AccessColumn {
            id: column

            width: parent.width
            access: access
        }

        VerticalScrollDecorator {}
    }
}
