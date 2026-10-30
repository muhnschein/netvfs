// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbplugin.h"
#include "rsbackend.h"

namespace NetVfs {

QString SmbBackendFactory::provider() const
{
    return QStringLiteral("smb");
}

Result SmbBackendFactory::create(Backend **out)
{
    return Rs::createBackend(provider(), out);
}

}