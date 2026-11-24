// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

Page {
    id: page

    property alias consumerId: access.consumerId
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
