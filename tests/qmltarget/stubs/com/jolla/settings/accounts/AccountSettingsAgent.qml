// SPDX-License-Identifier: LGPL-2.1-or-later
// Stub of the closed type with exactly the members of SPEC 7.1 (risk R1).
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
