// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.jolla.settings.accounts 1.0

AccountBusyPage {
    id: page

    signal pageActivated()
    signal editRequested()
    signal left()

    property bool _wasActivated

    function showBusy(text) {
        busyDescription = text
        state = "busy"
    }

    function showError(heading, text, detail) {
        infoHeading = heading
        infoDescription = text
        infoExtraDescription = detail
        //% "Go back and edit"
        infoButtonText = qsTrId("settings-accounts-netvfs-bt-go_back")
        state = "info"
    }

    onInfoButtonClicked: editRequested()

    onStatusChanged: {
        if (status === PageStatus.Active && !_wasActivated) {
            _wasActivated = true
            pageActivated()
        } else if (status === PageStatus.Inactive && _wasActivated && state === "busy") {
            left()
        }
    }
}
