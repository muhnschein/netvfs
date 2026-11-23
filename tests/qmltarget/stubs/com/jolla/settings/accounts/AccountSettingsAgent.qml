// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0

Item {
    property int accountId
    property QtObject accountProvider
    property QtObject accountManager
    property string accountsHeaderText
    property bool delayDeletion
    property bool accountIsReadOnly
    property bool accountNotSignedIn
    property Item initialPage

    signal accountDeletionRequested()
}
