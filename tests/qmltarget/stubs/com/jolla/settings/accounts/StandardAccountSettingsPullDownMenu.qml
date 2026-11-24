// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0

PullDownMenu {
    property bool allowSync
    property bool allowCredentialsUpdate
    property bool allowDelete

    signal credentialsUpdateRequested()
    signal accountDeletionRequested()
    signal syncRequested()
}
