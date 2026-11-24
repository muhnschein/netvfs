// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_ERRORTEXTS_H
#define NETVFS_QML_ERRORTEXTS_H

#include "error.h"

namespace NetVfsUi {
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
