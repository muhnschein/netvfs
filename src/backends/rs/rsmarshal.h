// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSMARSHAL_H
#define NETVFS_RSMARSHAL_H

// Conversions between NetVfs types and netvfs_rs.h data. Towards Rust everything is borrowed for
// the call; what Rust returns is one block each, released with the table's free.
#include "marshal.h"
#include "netvfs_rs.h"
#include "sshkeys.h"

#include <memory>

namespace NetVfs::Rs {

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

nvb_bytes view(const QByteArray &data);
// Bytes of a path; a name Names::decode() cannot produce has none: InvalidName.
Result encodePath(const QString &path, QByteArray *out);

Result resultOf(const nvr_table *table, nvb_error *error);

Entry entryOf(const nvb_entry &entry);
Capabilities capabilitiesOf(const nvb_capabilities &capabilities);
ServerIdentity identityOf(const nvb_identity &identity);
SshKeyMaterial keyOf(const nvr_key &key);

nvb_params paramsOf(Ffi::HoldArena &arena, const ConnectionParams &params);
nvb_attributes attributesOf(const AttributeChanges &changes);
nvr_write_opts writeOptionsOf(const WriteOptions &options);
nvb_upload_opts uploadOptionsOf(const WriteOptions &options);

}
#endif
