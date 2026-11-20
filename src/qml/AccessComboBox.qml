// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import Sailfish.Silica 1.0

// What an app may do: a level or "denied"; also "ask" with `withAsk` (new accounts).
ComboBox {
    id: box

    property string choice
    property bool withAsk
    readonly property var choices: withAsk ? ["ask", "full", "read-add", "read", "add", "denied"]
                                           : ["full", "read-add", "read", "add", "denied"]

    signal chosen(string picked)

    function text(word) {
        switch (word) {
        case "ask":
            //% "Ask me"
            return qsTrId("settings-accounts-netvfs-me-access_ask")
        case "full":
            //% "Full access"
            return qsTrId("settings-accounts-netvfs-me-access_full")
        case "read-add":
            //% "Read and add"
            return qsTrId("settings-accounts-netvfs-me-access_read_add")
        case "read":
            //% "Read only"
            return qsTrId("settings-accounts-netvfs-me-access_read")
        case "add":
            //% "Add only"
            return qsTrId("settings-accounts-netvfs-me-access_add")
        }
        //% "Not allowed"
        return qsTrId("settings-accounts-netvfs-me-access_denied")
    }

    width: parent ? parent.width : implicitWidth
    currentIndex: choices.indexOf(choice)
    menu: ContextMenu {
        Repeater {
            model: box.choices

            MenuItem {
                text: box.text(modelData)
            }
        }
    }
    onCurrentIndexChanged: {
        if (currentIndex >= 0 && currentIndex < choices.length && choices[currentIndex] !== choice) {
            chosen(choices[currentIndex])
        }
    }
}
