// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpplugin.h"
#include "ftpbackend.h"

namespace NetVfs {

QString FtpBackendFactory::provider() const
{
    return QStringLiteral("ftp");
}

Backend *FtpBackendFactory::create()
{
    return Ftp::createFtpBackend();
}

} // namespace NetVfs
