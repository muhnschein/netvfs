// SPDX-License-Identifier: LGPL-2.1-or-later
#include "shellexec.h"

namespace NetVfs {

ShellExec::~ShellExec() = default;

ShellExec *ShellExec::of(Backend *backend)
{
    if (!backend || !backend->capabilities().has(Capability::ShellExec))
        return nullptr;
    return dynamic_cast<ShellExec *>(backend);
}

} // namespace NetVfs
