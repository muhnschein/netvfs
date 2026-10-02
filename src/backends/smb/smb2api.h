// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMB2API_H
#define NETVFS_SMB2API_H

// The libsmb2 public headers are not self-contained (SPEC-smb section 6):
// <stdint.h> and <time.h> must come first.
#include <stdint.h>
#include <time.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/smb2-errors.h>

#endif
