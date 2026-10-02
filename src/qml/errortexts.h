// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_ERRORTEXTS_H
#define NETVFS_QML_ERRORTEXTS_H

#include "error.h"

namespace NetVfsUi {

// What the user was doing when the error happened; selects a specific
// message where the generic one would mislead (SPEC U-4).
enum class Activity {
    Connect,          // identify / verify / test connection
    StoredSecret,     // reading the stored secret from signond
    InstallKey,       // installing the public key with a password
    KeyFile,          // importing or generating a key
    Browse,           // verifying an account for the Files service (SPEC-v2 XA-1)
    ServicePolicy     // checking a configuration against a service (SPEC-v2 XA-4)
};

// Translated, user-facing sentence for an error.
QString userErrorText(NetVfs::Error error, Activity activity = Activity::Connect);
// Shown when the backend plugin for a provider is not installed.
QString backendMissingText();

} // namespace NetVfsUi

#endif
