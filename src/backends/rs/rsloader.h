// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSLOADER_H
#define NETVFS_RSLOADER_H

#include "error.h"
#include "netvfs_rs.h"

namespace NetVfs::Rs {

// The table of libnetvfs-rs.so (design §1.3). The first call that finds the
// library loads it with dlopen(RTLD_NOW | RTLD_LOCAL) from $NETVFS_RS_LIB
// (tests only) or the installed path, and it stays loaded for the life of
// the process. Without it: nullptr, and Internal "netvfs Rust backends not
// installed" in `*result`, with the loader's reason as the detail; the next
// call looks again.
const nvr_table *table(Result *result);

} // namespace NetVfs::Rs

#endif
