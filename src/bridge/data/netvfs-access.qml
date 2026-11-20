// SPDX-License-Identifier: LGPL-2.1-or-later
import QtQuick 2.0
import org.netvfs.accounts 1.0

// Settings entry accounts/netvfs_access (netvfs-access.json): the bridge's request notification opens it
// (handoff.conf OpenAccessRequest), so it shows the request of the first app waiting for the user.
NetVfsConsentPage {
    openRequest: true
}
