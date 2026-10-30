// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSLOADER_H
#define NETVFS_RSLOADER_H

#include "error.h"
#include "netvfs_rs.h"

namespace NetVfs::Rs {

// First call loads the library with dlopen(RTLD_NOW | RTLD_LOCAL) from $NETVFS_RS_LIB (tests only)
// or the installed path; stays loaded. Missing:
// nullptr and Internal "netvfs Rust backends not installed" in `*result`; the next call looks
// again.
const nvr_table *table(Result *result);

}
#endif
