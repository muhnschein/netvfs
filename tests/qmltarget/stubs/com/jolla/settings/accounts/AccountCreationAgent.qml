// SPDX-License-Identifier: LGPL-2.1-or-later
// Stub of the closed type with the members the account UI uses.
import QtQuick 2.0

Item {
    property Item initialPage
    property bool delayDeletion
    property QtObject accountManager
    property QtObject accountProvider
    property var endDestination
    property int endDestinationAction
    property var endDestinationProperties
    property var endDestinationReplaceTarget

    signal accountCreated(int accountId)
    signal accountCreationError(string errorMessage)
    signal goToEndDestination()
}
