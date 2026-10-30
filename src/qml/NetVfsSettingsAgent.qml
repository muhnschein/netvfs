// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import com.jolla.settings.accounts 1.0
import org.netvfs.accounts 1.0

AccountSettingsAgent {
    id: root

    property string provider

    initialPage: NetVfsSettingsPage {
        agent: root
        provider: root.provider
    }
}
