// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.jolla.settings.accounts 1.0

// AccountBusyPage while a connection test or an account write runs. A failure switches it to the
// info state with a specific message and a button back to editing.
AccountBusyPage {
    id: page

    // Emitted once, when the page first becomes active (after the push transition, so the owner may
    // replace the page when work completes).
    signal pageActivated()
    signal editRequested()
    // Emitted when the page stops being current while work still runs (user went back): the owner
    // cancels that work.
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
