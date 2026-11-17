// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_IDENTITY_H
#define NETVFS_IDENTITY_H

#include "backend.h"

namespace NetVfs {

// Compare identity seen in connect() with the pin: none and no pin = success; no pin =
// ServerIdentityUnknown (ask user); equal = success; else ServerIdentityChanged.
NETVFS_EXPORT Result checkServerIdentity(const ServerIdentity &seen, const QString &pin);

// Connect, verify identity against params.options["host_key"], only then authenticate. Identity
// failure disconnects before anything else is sent. `prompter` null for backups.
NETVFS_EXPORT Result establish(Backend *backend, const ConnectionParams &params,
                               const Credentials &credentials, ServerIdentity *seen = nullptr,
                               AuthPrompter *prompter = nullptr);

}
#endif
