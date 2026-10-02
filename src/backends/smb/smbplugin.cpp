// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbplugin.h"
#include "smbbackend.h"

#include <memory>

namespace NetVfs {

QString SmbBackendFactory::provider() const
{
    return QStringLiteral("smb");
}

Backend *SmbBackendFactory::create()
{
    return std::make_unique<Smb::SmbBackend>().release();   // the caller owns it
}

} // namespace NetVfs
