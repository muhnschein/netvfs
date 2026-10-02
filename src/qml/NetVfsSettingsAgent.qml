// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

// Settings UI (SPEC 7.4) shared by sftp-settings.qml and smb-settings.qml.
AccountSettingsAgent {
    id: root

    property string provider

    initialPage: NetVfsSettingsPage {
        agent: root
        provider: root.provider
    }
}
