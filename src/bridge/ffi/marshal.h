// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_FFI_MARSHAL_H
#define NETVFS_BRIDGE_FFI_MARSHAL_H

// Conversions between NetVfs types and the flat data of the C ABI. Every conversion towards C is
// written once, as a template over an "arena" that provides the memory:
//   HoldArena: objects live as long as the arena; for data handed to a callback.
//   SizeArena and BlockArena: pack() measures an object with the first and fills ONE malloc'd block
//     with the second, so the caller releases it with a single free().
#include "netvfs_bridge_ffi.h"

#include "error.h"
#include "names.h"
#include "types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVariant>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <new>
#include <type_traits>
#include <vector>

namespace NetVfs::Ffi {

// Arrays and the head object start at this alignment inside a block.
constexpr size_t BlockAlign = alignof(std::max_align_t);

constexpr size_t alignUp(size_t n)
{
    return (n + BlockAlign - 1) / BlockAlign * BlockAlign;
}

class HoldArena
{
public:
    nvb_bytes bytes(const QByteArray &data)
    {
        const QByteArray &held = m_bytes.emplace_back(data);
        return nvb_bytes { reinterpret_cast<const uint8_t *>(held.constData()), static_cast<size_t>(held.size()) };
    }

    template <typename T>
    T *array(size_t n)
    {
        auto owned = std::make_unique<T[]>(n);
        T *items = owned.get();
        m_arrays.emplace_back(std::move(owned));
        return items;
    }

private:
    std::deque<QByteArray> m_bytes;
    std::vector<std::shared_ptr<void>> m_arrays;
};

// Measures a block. The arrays it hands out are scratch memory so the filling code runs unchanged.
class SizeArena
{
public:
    nvb_bytes bytes(const QByteArray &data)
    {
        m_dataBytes += static_cast<size_t>(data.size());
        return nvb_bytes { nullptr, static_cast<size_t>(data.size()) };
    }

    template <typename T>
    T *array(size_t n)
    {
        m_arrayBytes += alignUp(n * sizeof(T));
        return m_scratch.array<T>(n);
    }

    size_t arrayBytes() const { return m_arrayBytes; }
    size_t dataBytes() const { return m_dataBytes; }

private:
    HoldArena m_scratch;
    size_t m_arrayBytes = 0;
    size_t m_dataBytes = 0;
};

class BlockArena
{
public:
    BlockArena(char *arrays, char *data) : m_arrays(arrays), m_data(data) {}

    // Never a null pointer, also for empty data (one past the block at most).
    nvb_bytes bytes(const QByteArray &data)
    {
        const auto size = static_cast<size_t>(data.size());
        if (size > 0)
            std::memcpy(m_data, data.constData(), size);
        const nvb_bytes out { reinterpret_cast<const uint8_t *>(m_data), size };
        m_data += size;
        return out;
    }

    // Array created in the block by placement array new, whose result points to its first element
    // (no array cookie: CWG 2382).
    template <typename T>
    T *array(size_t n)
    {
        static_assert(std::is_trivially_destructible_v<T>, "released with free() alone");
        static_assert(alignof(T) <= BlockAlign, "arrays start at BlockAlign");
        auto *items = ::new (static_cast<void *>(m_arrays)) T[n] {};
        m_arrays += alignUp(n * sizeof(T));
        return items;
    }

private:
    char *m_arrays;
    char *m_data;
};

// One malloc'd block holding a T and everything it points to. `fill` is called as fill(arena, T *)
// twice: to measure, then to fill. Caller releases with free() and runs no destructor, so nothing
// in it may need one.
template <typename T, typename Fill>
T *pack(const Fill &fill)
{
    static_assert(std::is_trivially_destructible_v<T>, "released with free() alone");
    static_assert(alignof(T) <= BlockAlign, "malloc() aligns the head to max_align_t");
    SizeArena size;
    T scratch {};
    fill(size, &scratch);
    const size_t head = alignUp(sizeof(T));
    void *raw = std::malloc(head + size.arrayBytes() + size.dataBytes());
    if (!raw)
        throw std::bad_alloc();
    auto *out = ::new (raw) T {};
    auto *base = static_cast<char *>(raw);
    BlockArena block(base + head, base + head + size.arrayBytes());
    fill(block, out);
    return out;
}

// Copies. Throws std::length_error above the QByteArray limit.
QByteArray toByteArray(nvb_bytes bytes);
QString toUtf8String(nvb_bytes bytes);
// Protocol bytes to a lossless QString (Names::decode).
QString toPath(nvb_bytes bytes);
// Unknown value kind is a ProtocolError.
Result toParams(const nvb_params &in, ConnectionParams *out);
QDateTime fromMs(int64_t ms);

qint64 toMs(const QDateTime &time);
// NVB_VALUE_* for a value the ABI can carry, 0 for any other (dates as ISO-8601 UTC strings).
uint32_t valueKind(const QVariant &value);

template <typename Arena>
void fillValue(Arena &arena, nvb_value *out, const QVariant &value)
{
    out->kind = valueKind(value);
    switch (out->kind) {
    case NVB_VALUE_STRING:
        out->bytes = arena.bytes(value.type() == QVariant::DateTime
                                     ? value.toDateTime().toUTC().toString(Qt::ISODate).toUtf8()
                                     : value.toString().toUtf8());
        break;
    case NVB_VALUE_BOOL:
        out->number = value.toBool() ? 1 : 0;
        break;
    case NVB_VALUE_INT:
        out->number = value.toLongLong();
        break;
    case NVB_VALUE_BYTES:
        out->bytes = arena.bytes(value.toByteArray());
        break;
    case NVB_VALUE_STRING_LIST: {
        const QStringList items = value.toStringList();
        nvb_bytes *list = arena.template array<nvb_bytes>(static_cast<size_t>(items.size()));
        for (int i = 0; i < items.size(); ++i)
            list[i] = arena.bytes(items.at(i).toUtf8());
        out->items = list;
        out->n_items = static_cast<size_t>(items.size());
        break;
    }
    default:
        break;
    }
}

// The values of `map` the ABI can carry, in key order; picked once so the array has exactly one
// element per written value.
template <typename Arena>
const nvb_kv *fillMap(Arena &arena, const QVariantMap &map, size_t *count)
{
    std::vector<QVariantMap::const_iterator> carried;
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        if (valueKind(it.value()) != 0)
            carried.push_back(it);
    }
    const size_t n = carried.size();
    nvb_kv *kv = arena.template array<nvb_kv>(n);
    for (size_t i = 0; i < n; ++i) {
        kv[i].key = arena.bytes(carried[i].key().toUtf8());
        fillValue(arena, &kv[i].value, carried[i].value());
    }
    *count = n;
    return kv;
}

template <typename Arena>
void fillEntry(Arena &arena, nvb_entry *out, const Entry &entry)
{
    out->name = arena.bytes(Names::encode(entry.name));
    out->type = static_cast<uint8_t>(entry.type);
    out->target_type = static_cast<uint8_t>(entry.targetType);
    out->flags = static_cast<uint16_t>(entry.flags);
    out->mode = entry.mode;
    out->size = entry.size;
    out->mtime_ms = toMs(entry.modified);
    out->ctime_ms = toMs(entry.created);
    out->atime_ms = toMs(entry.accessed);
    out->uid = entry.uid;
    out->gid = entry.gid;
    out->owner = arena.bytes(entry.owner.toUtf8());
    out->group = arena.bytes(entry.group.toUtf8());
    out->etag = arena.bytes(entry.etag);
    out->content_type = arena.bytes(entry.contentType.toUtf8());
}

template <typename Arena>
void fillError(Arena &arena, nvb_error *out, const Result &result)
{
    out->name = arena.bytes(errorName(result.error()).toUtf8());
    out->message = arena.bytes(result.message().toUtf8());
    out->detail = arena.bytes(result.detail().toUtf8());
    out->retry_after_ms = result.retryAfterMs();
}

// nullptr for success; else one block.
nvb_error *packError(const Result &result);
nvb_blob *packBlob(const QByteArray &data);
nvb_entry *packEntry(const Entry &entry);
nvb_capabilities *packCapabilities(const Capabilities &capabilities);
nvb_url *packUrl(const ConnectionParams &params, const QString &path);

}
#endif
