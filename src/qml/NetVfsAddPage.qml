// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.jolla.settings.accounts 1.0

// Settings entry accounts/netvfs_add_<provider> (handoff.conf AddAccount): starts that provider's
// creation flow past the Accounts list; pops itself once the flow is done or cancelled.
Page {
    id: page

    property string provider
    property bool _started

    AccountCreationManager {
        id: creation
        endDestination: page
        endDestinationAction: PageStackAction.Pop
    }

    onStatusChanged: {
        if (status !== PageStatus.Active)
            return
        if (_started) {
            pageStack.pop()
        } else {
            _started = true
            creation.startAccountCreationForProvider(provider)
        }
    }
}
