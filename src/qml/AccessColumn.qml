// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0
import org.netvfs.accounts 1.0

// The app's name, the level it asks for, a level per account and for new accounts (NetVfsAccessPage,
// NetVfsAccessRequestDialog).
Column {
    id: column

    property NetVfsAccessModel access
    property string description: access ? askedText(access.asked) : ""
    property string explanation

    function askedText(level) {
        switch (level) {
        case "full":
            //% "Asks for full access"
            return qsTrId("settings-accounts-netvfs-la-access_asks_full")
        case "read-add":
            //% "Asks to read and add"
            return qsTrId("settings-accounts-netvfs-la-access_asks_read_add")
        case "add":
            //% "Asks to add only"
            return qsTrId("settings-accounts-netvfs-la-access_asks_add")
        }
        //% "Asks to read only"
        return qsTrId("settings-accounts-netvfs-la-access_asks_read")
    }

    width: parent.width

    PageHeader {
        title: column.access ? column.access.displayName : ""
        description: column.description
    }

    Label {
        visible: text !== ""
        x: Theme.horizontalPageMargin
        width: parent.width - 2 * x
        wrapMode: Text.Wrap
        color: Theme.secondaryHighlightColor
        font.pixelSize: Theme.fontSizeSmall
        text: column.explanation
    }

    SectionHeader {
        visible: accounts.count > 0
        //% "Accounts"
        text: qsTrId("settings-accounts-netvfs-he-access_accounts")
    }

    Repeater {
        id: accounts

        model: column.access

        AccessComboBox {
            label: model.name
            choice: model.choice
            onChosen: column.access.setChoice(model.accountId, picked)
        }
    }

    SectionHeader {
        //% "New accounts"
        text: qsTrId("settings-accounts-netvfs-he-access_new_accounts")
    }

    AccessComboBox {
        withAsk: true
        //% "Level"
        label: qsTrId("settings-accounts-netvfs-la-access_level")
        choice: column.access ? column.access.newAccounts : ""
        onChosen: column.access.setNewAccounts(picked)
    }

    Item {
        width: 1
        height: Theme.paddingLarge
    }
}
