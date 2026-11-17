// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_ERRORTEXTS_H
#define NETVFS_QML_ERRORTEXTS_H

#include "error.h"

namespace NetVfsUi {

// What the user was doing when the error happened; selects a specific message where the generic one
// would mislead.
enum class Activity {
    Connect,
    StoredSecret,
    InstallKey,
    KeyFile,
    Browse,
    ServicePolicy
};

QString userErrorText(NetVfs::Error error, Activity activity = Activity::Connect);
QString backendMissingText();

}
#endif
