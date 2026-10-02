// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_IDENTITY_H
#define NETVFS_IDENTITY_H

#include "backend.h"

namespace NetVfs {

// SPEC-sftp S-7: compare the identity seen during connect() with the pin.
//  - protocol without identity and no pin: success
//  - no pin: ServerIdentityUnknown (caller asks the user)
//  - equal: success
//  - otherwise: ServerIdentityChanged
NETVFS_EXPORT Result checkServerIdentity(const ServerIdentity &seen, const QString &pin);

// SEC-1 / C-7: connect, verify the identity against params.options["host_key"],
// and only then authenticate. On an identity failure the backend is
// disconnected before anything else is sent.
NETVFS_EXPORT Result establish(Backend *backend, const ConnectionParams &params,
                               const Credentials &credentials, ServerIdentity *seen = nullptr);

} // namespace NetVfs

#endif
