// SPDX-License-Identifier: LGPL-2.1-or-later
#include "webdavplugin.h"
#include "rsbackend.h"

namespace NetVfs {

QString WebDavBackendFactory::provider() const
{
    return QStringLiteral("webdav");
}

Result WebDavBackendFactory::create(Backend **out)
{
    return Rs::createBackend(provider(), out);
}

}