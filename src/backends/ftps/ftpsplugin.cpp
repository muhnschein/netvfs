// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ftpsplugin.h"
#include "rsbackend.h"

namespace NetVfs {

QString FtpsBackendFactory::provider() const
{
    return QStringLiteral("ftps");
}

Result FtpsBackendFactory::create(Backend **out)
{
    return Rs::createBackend(provider(), out);
}

}