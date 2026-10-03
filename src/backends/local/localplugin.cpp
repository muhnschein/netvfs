// SPDX-License-Identifier: LGPL-2.1-or-later
#include "localplugin.h"
#include "localbackend.h"

#include <memory>

namespace NetVfs {

QString LocalBackendFactory::provider() const
{
    return QStringLiteral("local");
}

Backend *LocalBackendFactory::create()
{
    return std::make_unique<Local::LocalBackend>().release();   // the caller owns it
}

} // namespace NetVfs
