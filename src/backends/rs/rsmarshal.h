// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSMARSHAL_H
#define NETVFS_RSMARSHAL_H

// Conversions between NetVfs types and the data of netvfs_rs.h (design §2),
// next to Phase 2's (src/bridge/ffi/marshal.h), whose types they share.
// Towards Rust everything is borrowed for the call (R1); what Rust returns
// is one block each, released with the table's free (R3).
#include "marshal.h"
#include "netvfs_rs.h"
#include "sshkeys.h"

#include <memory>

namespace NetVfs::Rs {

// Releases a block of the table (R3); free also wipes it.
class Free
{
public:
    explicit Free(const nvr_table *table) : m_table(table) {}

    template <typename T>
    void operator()(T *block) const
    {
        m_table->free(block);
    }

private:
    const nvr_table *m_table;
};

template <typename T>
using Block = std::unique_ptr<T, Free>;

// A view of `data` for the call (R1).
nvb_bytes view(const QByteArray &data);
// XC-4: the bytes of a path; a name that Names::decode() cannot produce has
// none and is InvalidName.
Result encodePath(const QString &path, QByteArray *out);

// The result of a table call; releases `error`.
Result resultOf(const nvr_table *table, nvb_error *error);

Entry entryOf(const nvb_entry &entry);
Capabilities capabilitiesOf(const nvb_capabilities &capabilities);
ServerIdentity identityOf(const nvb_identity &identity);
SshKeyMaterial keyOf(const nvr_key &key);

// Towards Rust; the bytes stay in `arena`.
nvb_params paramsOf(Ffi::HoldArena &arena, const ConnectionParams &params);
nvb_attributes attributesOf(const AttributeChanges &changes);
nvr_write_opts writeOptionsOf(const WriteOptions &options);
nvb_upload_opts uploadOptionsOf(const WriteOptions &options);

} // namespace NetVfs::Rs

#endif
