// SPDX-License-Identifier: LGPL-2.1-or-later
#include "webdavplugin.h"
#include "webdavbackend.h"

#include <memory>

namespace NetVfs {

QString WebDavBackendFactory::provider() const
{
    return QStringLiteral("webdav");
}

Backend *WebDavBackendFactory::create()
{
    return std::make_unique<WebDav::WebDavBackend>().release();   // the caller owns it
}

} // namespace NetVfs
