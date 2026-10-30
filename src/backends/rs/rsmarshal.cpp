// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rsmarshal.h"

namespace NetVfs::Rs {

using Ffi::toByteArray;
using Ffi::toUtf8String;

static_assert(static_cast<uint32_t>(WriteOptions::Disposition::CreateNew) == NVB_DISPOSITION_CREATE_NEW);
static_assert(static_cast<uint32_t>(WriteOptions::Disposition::Truncate) == NVB_DISPOSITION_TRUNCATE);
static_assert(static_cast<uint32_t>(WriteOptions::Disposition::Resume) == NVB_DISPOSITION_RESUME);

namespace {

// -1 is unknown (invalid QDateTime), as Ffi::toMs() writes it.
QDateTime timeOf(int64_t ms)
{
    return ms == -1 ? QDateTime() : Ffi::fromMs(ms);
}

}
nvb_bytes view(const QByteArray &data)
{
    return nvb_bytes { reinterpret_cast<const uint8_t *>(data.constData()), static_cast<size_t>(data.size()) };
}

Result encodePath(const QString &path, QByteArray *out)
{
    if (!Names::isEncodable(path))
        return Result(Error::InvalidName, QStringLiteral("%1 is not a name the server can store").arg(Names::display(path)));
    *out = Names::encode(path);
    return Result::success();
}

Result resultOf(const nvr_table *table, nvb_error *error)
{
    if (!error)
        return Result::success();
    const Block<nvb_error> block(error, Free(table));
    return Result(errorFromName(toUtf8String(error->name)), toUtf8String(error->message),
                  toUtf8String(error->detail), error->retry_after_ms);
}

Entry entryOf(const nvb_entry &entry)
{
    Entry out;
    out.name = Names::decode(toByteArray(entry.name));
    out.type = static_cast<EntryType>(entry.type);
    out.targetType = static_cast<EntryType>(entry.target_type);
    out.flags = EntryFlags(QFlag(entry.flags));
    out.mode = entry.mode;
    out.size = entry.size;
    out.modified = timeOf(entry.mtime_ms);
    out.created = timeOf(entry.ctime_ms);
    out.accessed = timeOf(entry.atime_ms);
    out.uid = entry.uid;
    out.gid = entry.gid;
    out.owner = toUtf8String(entry.owner);
    out.group = toUtf8String(entry.group);
    out.etag = toByteArray(entry.etag);
    out.contentType = toUtf8String(entry.content_type);
    return out;
}

Capabilities capabilitiesOf(const nvb_capabilities &capabilities)
{
    Capabilities out;
    for (size_t i = 0; i < capabilities.n_flags; ++i) {
        Capability flag {};
        if (capabilityFromName(toUtf8String(capabilities.flags[i]), &flag))
            out.flags.insert(flag);
    }
    for (size_t i = 0; i < capabilities.n_checksum_algorithms; ++i)
        out.checksumAlgorithms << toUtf8String(capabilities.checksum_algorithms[i]);
    out.maxNameBytes = capabilities.max_name_bytes;
    return out;
}

ServerIdentity identityOf(const nvb_identity &identity)
{
    ServerIdentity out;
    out.kind = identity.kind == NVB_IDENTITY_SSH ? ServerIdentity::Kind::SshHostKey : ServerIdentity::Kind::None;
    out.algorithm = toUtf8String(identity.algorithm);
    out.publicKey = toByteArray(identity.public_key);
    out.fingerprint = toUtf8String(identity.fingerprint);
    return out;
}

SshKeyMaterial keyOf(const nvr_key &key)
{
    SshKeyMaterial out;
    out.privateKey = toByteArray(key.private_key);
    out.algorithm = toUtf8String(key.algorithm);
    out.publicLine = toUtf8String(key.public_line);
    out.fingerprint = toUtf8String(key.fingerprint);
    return out;
}

nvb_params paramsOf(Ffi::HoldArena &arena, const ConnectionParams &params)
{
    nvb_params out {};
    out.provider = arena.bytes(params.provider.toUtf8());
    out.host = arena.bytes(params.host.toUtf8());
    out.port = params.port;
    out.username = arena.bytes(params.username.toUtf8());
    out.options = Ffi::fillMap(arena, params.options, &out.n_options);
    out.connect_timeout_ms = params.connectTimeoutMs;
    out.request_timeout_ms = params.requestTimeoutMs;
    return out;
}

nvb_attributes attributesOf(const AttributeChanges &changes)
{
    nvb_attributes out {};
    out.mode = changes.mode;
    out.has_mtime = changes.modified.isValid() ? 1 : 0;
    out.mtime_ms = Ffi::toMs(changes.modified);
    out.has_atime = changes.accessed.isValid() ? 1 : 0;
    out.atime_ms = Ffi::toMs(changes.accessed);
    return out;
}

nvr_write_opts writeOptionsOf(const WriteOptions &options)
{
    nvr_write_opts out {};
    out.disposition = static_cast<uint32_t>(options.disposition);
    out.create_mode = options.createMode;
    out.resume_offset = options.resumeOffset;
    out.expected_size = options.expectedSize;
    out.has_mtime = options.modified.isValid() ? 1 : 0;
    out.mtime_ms = Ffi::toMs(options.modified);
    return out;
}

nvb_upload_opts uploadOptionsOf(const WriteOptions &options)
{
    const nvr_write_opts write = writeOptionsOf(options);
    nvb_upload_opts out {};
    out.disposition = write.disposition;
    out.create_mode = write.create_mode;
    out.resume_offset = write.resume_offset;
    out.expected_size = write.expected_size;
    out.has_mtime = write.has_mtime;
    out.mtime_ms = write.mtime_ms;
    return out;
}

}