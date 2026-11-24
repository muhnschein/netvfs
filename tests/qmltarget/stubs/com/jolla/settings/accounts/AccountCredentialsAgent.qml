// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0

Item {
    property int accountId
    property QtObject accountProvider
    property QtObject accountManager
    property Item initialPage
    property var endDestination
    property int endDestinationAction
    property var endDestinationProperties
    property var endDestinationReplaceTarget
    property bool delayDeletion
    property bool canCancelUpdate

    signal credentialsUpdated(int accountId)
    signal credentialsUpdateError(string errorMessage)
    signal goToEndDestination()
}
