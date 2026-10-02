// SPDX-License-Identifier: LGPL-2.1-or-later
//
// SPEC 10.2 gate G-SMB item 4 and SPEC-smb M-6: no DCE/RPC in the plugin.
//
// The libsmb2 build has Kerberos and the separate libdcerpc switched off, but
// libsmb2 itself still embeds a small DCE/RPC client for NetrShareEnum. It is
// only reachable through smb2_share_enum_async(), which the backend never
// calls; the archive member holding it would still be linked in, because the
// synchronous wrappers (sync.c, pulled in by libsmb2.c) refer to it.
//
// Defining the symbol here resolves that reference before the archive is
// searched, so neither the share enumeration nor the DCE/RPC parser is linked.
// Should a future libsmb2 pull the archive member in for another reason, the
// link fails with a duplicate definition instead of silently adding the code.
#include "smb2api.h"

#include <smb2/libsmb2-share-enum.h>

#include <cerrno>

extern "C" int smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum,
                                     smb2_command_cb, void *) // NOSONAR(cpp:S5008) libsmb2's C signature
{
    smb2_set_error(smb2, "Share enumeration is not available");
    return -ENOTSUP;
}
