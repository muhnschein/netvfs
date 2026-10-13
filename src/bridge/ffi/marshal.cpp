// SPDX-License-Identifier: LGPL-2.1-or-later
#include "marshal.h"

#include <climits>
#include <stdexcept>

namespace NetVfs::Ffi {

QByteArray toByteArray(nvb_bytes bytes)
{
    if (bytes.len > static_cast<size_t>(INT_MAX))
        throw std::length_error("byte string too long");
    if (bytes.len == 0)
        return QByteArray();
    return QByteArray(reinterpret_cast<const char *>(bytes.ptr), static_cast<int>(bytes.len));
}

QString toUtf8String(nvb_bytes bytes)
{
    return QString::fromUtf8(toByteArray(bytes));
}

QString toPath(nvb_bytes bytes)
{
    return Names::decode(toByteArray(bytes));
}

QDateTime fromMs(int64_t ms)
{
    return QDateTime::fromMSecsSinceEpoch(ms, Qt::UTC);
}

qint64 toMs(const QDateTime &time)
{
    return time.isValid() ? time.toMSecsSinceEpoch() : -1;
}

namespace {

QStringList toStringList(const nvb_value &value)
{
    QStringList list;
    for (size_t i = 0; i < value.n_items; ++i)
        list << toUtf8String(value.items[i]);
    return list;
}

bool toVariant(const nvb_value &value, QVariant *out)
{
    switch (value.kind) {
    case NVB_VALUE_STRING:
        *out = toUtf8String(value.bytes);
        return true;
    case NVB_VALUE_BOOL:
        *out = value.number != 0;
        return true;
    case NVB_VALUE_INT:
        *out = static_cast<qlonglong>(value.number);
        return true;
    case NVB_VALUE_BYTES:
        *out = toByteArray(value.bytes);
        return true;
    case NVB_VALUE_STRING_LIST:
        *out = toStringList(value);
        return true;
    default:
        return false;
    }
}

} // namespace

Result toParams(const nvb_params &in, ConnectionParams *out)
{
    ConnectionParams params;
    params.provider = toUtf8String(in.provider);
    params.host = toUtf8String(in.host);
    params.port = in.port;
    params.username = toUtf8String(in.username);
    params.connectTimeoutMs = in.connect_timeout_ms;
    params.requestTimeoutMs = in.request_timeout_ms;
    for (size_t i = 0; i < in.n_options; ++i) {
        QVariant value;
        if (!toVariant(in.options[i].value, &value))
            return Result(Error::ProtocolError, QStringLiteral("Unknown option value kind"));
        params.options.insert(toUtf8String(in.options[i].key), value);
    }
    *out = params;
    return Result::success();
}

uint32_t valueKind(const QVariant &value)
{
    switch (static_cast<int>(value.type())) {
    case QMetaType::QString:
    case QMetaType::QDateTime:
        return NVB_VALUE_STRING;
    case QMetaType::Bool:
        return NVB_VALUE_BOOL;
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
        return NVB_VALUE_INT;
    case QMetaType::QByteArray:
        return NVB_VALUE_BYTES;
    case QMetaType::QStringList:
        return NVB_VALUE_STRING_LIST;
    default:
        return 0;
    }
}

nvb_error *packError(const Result &result)
{
    if (result.ok())
        return nullptr;
    return pack<nvb_error>([&result](auto &arena, nvb_error *out) { fillError(arena, out, result); });
}

nvb_blob *packBlob(const QByteArray &data)
{
    return pack<nvb_blob>([&data](auto &arena, nvb_blob *out) { out->data = arena.bytes(data); });
}

nvb_entry *packEntry(const Entry &entry)
{
    return pack<nvb_entry>([&entry](auto &arena, nvb_entry *out) { fillEntry(arena, out, entry); });
}

namespace {

template <typename Arena>
const nvb_bytes *fillStrings(Arena &arena, const QStringList &strings, size_t *count)
{
    nvb_bytes *items = arena.template array<nvb_bytes>(static_cast<size_t>(strings.size()));
    for (int i = 0; i < strings.size(); ++i)
        items[i] = arena.bytes(strings.at(i).toUtf8());
    *count = static_cast<size_t>(strings.size());
    return items;
}

} // namespace

nvb_capabilities *packCapabilities(const Capabilities &capabilities)
{
    return pack<nvb_capabilities>([&capabilities](auto &arena, nvb_capabilities *out) {
        out->flags = fillStrings(arena, capabilities.names(), &out->n_flags);
        out->checksum_algorithms = fillStrings(arena, capabilities.checksumAlgorithms,
                                               &out->n_checksum_algorithms);
        out->max_name_bytes = capabilities.maxNameBytes;
    });
}

nvb_url *packUrl(const ConnectionParams &params, const QString &path)
{
    return pack<nvb_url>([&params, &path](auto &arena, nvb_url *out) {
        nvb_params &p = out->params;
        p.provider = arena.bytes(params.provider.toUtf8());
        p.host = arena.bytes(params.host.toUtf8());
        p.port = params.port;
        p.username = arena.bytes(params.username.toUtf8());
        p.options = fillMap(arena, params.options, &p.n_options);
        p.connect_timeout_ms = params.connectTimeoutMs;
        p.request_timeout_ms = params.requestTimeoutMs;
        out->path = arena.bytes(Names::encode(path));
    });
}

} // namespace NetVfs::Ffi
