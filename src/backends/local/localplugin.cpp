// SPDX-License-Identifier: LGPL-2.1-or-later
#include "localplugin.h"
#include "localbackend.h"

#include <memory>

namespace NetVfs {

QString LocalBackendFactory::provider() const
{
    return QStringLiteral("local");
}

Result LocalBackendFactory::create(Backend **out)
{
    *out = std::make_unique<Local::LocalBackend>().release();
    return Result::success();
}

}