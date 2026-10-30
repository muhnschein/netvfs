// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ffi_p.h"

#include "backendloader.h"

#include <algorithm>
#include <climits>
#include <cstring>
#include <functional>
#include <stdexcept>

nvb_conn::~nvb_conn()
{
    for (const auto &[key, handle] : handles) {
        if (handle->handle)
            handle->handle->close();
    }
    handles.clear();
    if (backend)
        backend->disconnect();
}

namespace NetVfs::Ffi {

namespace {

template <typename T>
void clearOut(T **out)
{
    if (out)
        *out = nullptr;
}

ReadHandle *readHandleOf(const nvb_handle *h)
{
    if (!h || !h->handle)
        throw std::invalid_argument("no handle");
    return h->handle.get();
}

// `sink` gets one backend batch and says whether to go on.
class SinkAdapter final : public ListSink
{
public:
    using Sink = std::function<bool(const nvb_entry *entries, size_t n)>;

    explicit SinkAdapter(Sink sink) : m_sink(std::move(sink)) {}

    bool entries(const QVector<Entry> &batch) override
    {
        HoldArena arena;
        std::vector<nvb_entry> items(static_cast<size_t>(batch.size()));
        for (int i = 0; i < batch.size(); ++i)
            fillEntry(arena, &items[static_cast<size_t>(i)], batch.at(i));
        return m_sink(items.data(), items.size());
    }

private:
    Sink m_sink;
};

}
nvb_error *connNew(nvb_bytes provider, nvb_conn **out) noexcept
{
    clearOut(out);
    return guarded([provider, out]() {
        if (!out)
            throw std::invalid_argument("no out-pointer");
        Result created;
        auto conn = std::make_unique<nvb_conn>();
        conn->backend.reset(BackendLoader::create(toUtf8String(provider), &created));
        if (!conn->backend)
            return created.ok() ? Result(Error::Unsupported, QStringLiteral("No backend for this provider")) : created;
        *out = conn.release();
        return Result::success();
    });
}

void connFree(nvb_conn *conn) noexcept
{
    guardedVoid([conn]() { std::unique_ptr<nvb_conn> owned(conn); });
}

// Any thread, also while an owner-thread call runs.
void connCancel(nvb_conn *conn) noexcept
{
    guardedVoid([conn]() {
        if (!conn)
            return;
        conn->canceled.store(true);
        if (conn->backend)
            conn->backend->cancel();
    });
}

void connResetCancel(nvb_conn *conn) noexcept
{
    guardedVoid([conn]() {
        backendOf(conn)->resetCancel();
        conn->canceled.store(false);
    });
}

nvb_error *connCapabilities(nvb_conn *conn, nvb_capabilities **out) noexcept
{
    clearOut(out);
    return guarded([conn, out]() {
        const Capabilities capabilities = backendOf(conn)->capabilities();
        if (out)
            *out = packCapabilities(capabilities);
        return Result::success();
    });
}

nvb_error *connStat(nvb_conn *conn, nvb_bytes path, int32_t follow, nvb_entry **out) noexcept
{
    clearOut(out);
    return guarded([conn, path, follow, out]() {
        Backend *backend = backendOf(conn);
        Entry entry;
        const Result r = follow ? backend->stat(toPath(path), &entry) : backend->lstat(toPath(path), &entry);
        if (r.ok() && out)
            *out = packEntry(entry);
        return r;
    });
}

nvb_error *connList(nvb_conn *conn, nvb_bytes dir, uint32_t batchSize, nvb_list_sink_fn sink, void *ctx) noexcept
{
    return guarded([conn, dir, batchSize, sink, ctx]() {
        Backend *backend = backendOf(conn);
        if (!sink)
            throw std::invalid_argument("no list sink");
        SinkAdapter adapter([sink, ctx](const nvb_entry *entries, size_t n) {
            return sink(ctx, entries, n) != 0;
        });
        ListOptions options;
        options.batchSize = static_cast<int>(std::min<uint32_t>(batchSize, INT_MAX));
        return backend->list(toPath(dir), &adapter, options);
    });
}

nvb_error *connReadLink(nvb_conn *conn, nvb_bytes path, nvb_blob **target) noexcept
{
    clearOut(target);
    return guarded([conn, path, target]() {
        QString link;
        const Result r = backendOf(conn)->readLink(toPath(path), &link);
        if (r.ok() && target)
            *target = packBlob(Names::encode(link));
        return r;
    });
}

nvb_error *connSpaceInfo(nvb_conn *conn, nvb_bytes path, nvb_space *out) noexcept
{
    return guarded([conn, path, out]() {
        SpaceInfo info;
        const Result r = backendOf(conn)->spaceInfo(toPath(path), &info);
        if (out)
            *out = nvb_space { info.free, info.total, info.used };
        return r;
    });
}

nvb_error *connChecksum(nvb_conn *conn, nvb_bytes path, nvb_bytes algorithm, nvb_blob **digest) noexcept
{
    clearOut(digest);
    return guarded([conn, path, algorithm, digest]() {
        QByteArray value;
        const Result r = backendOf(conn)->checksum(toPath(path), toUtf8String(algorithm), &value);
        if (r.ok() && digest)
            *digest = packBlob(value);
        return r;
    });
}

nvb_error *connMakeDir(nvb_conn *conn, nvb_bytes path, int32_t exclusive) noexcept
{
    return guarded([conn, path, exclusive]() { return backendOf(conn)->makeDir(toPath(path), exclusive != 0); });
}

nvb_error *connRemoveFile(nvb_conn *conn, nvb_bytes path) noexcept
{
    return guarded([conn, path]() { return backendOf(conn)->removeFile(toPath(path)); });
}

nvb_error *connRemoveDir(nvb_conn *conn, nvb_bytes path) noexcept
{
    return guarded([conn, path]() { return backendOf(conn)->removeDir(toPath(path)); });
}

nvb_error *connRename(nvb_conn *conn, nvb_bytes from, nvb_bytes to, int32_t replace) noexcept
{
    return guarded([conn, from, to, replace]() {
        return backendOf(conn)->rename(toPath(from), toPath(to),
                                       replace ? RenameMode::Replace : RenameMode::NoReplace);
    });
}

nvb_error *connSetAttributes(nvb_conn *conn, nvb_bytes path, const nvb_attributes *changes) noexcept
{
    return guarded([conn, path, changes]() {
        Backend *backend = backendOf(conn);
        if (!changes)
            throw std::invalid_argument("no attributes");
        AttributeChanges c;
        c.mode = changes->mode;
        if (changes->has_mtime)
            c.modified = fromMs(changes->mtime_ms);
        if (changes->has_atime)
            c.accessed = fromMs(changes->atime_ms);
        return backend->setAttributes(toPath(path), c);
    });
}

// Target is verbatim (not a normalised path).
nvb_error *connMakeSymlink(nvb_conn *conn, nvb_bytes target, nvb_bytes linkPath) noexcept
{
    return guarded([conn, target, linkPath]() {
        return backendOf(conn)->makeSymlink(toPath(target), toPath(linkPath));
    });
}

nvb_error *connMakeHardlink(nvb_conn *conn, nvb_bytes existing, nvb_bytes newPath) noexcept
{
    return guarded([conn, existing, newPath]() {
        return backendOf(conn)->makeHardlink(toPath(existing), toPath(newPath));
    });
}

nvb_error *connCopy(nvb_conn *conn, nvb_bytes from, nvb_bytes to, int32_t recursive, int32_t replace) noexcept
{
    return guarded([conn, from, to, recursive, replace]() {
        CopyOptions options;
        options.recursive = recursive != 0;
        options.mode = replace ? RenameMode::Replace : RenameMode::NoReplace;
        return backendOf(conn)->copy(toPath(from), toPath(to), options);
    });
}

nvb_error *connOpenRead(nvb_conn *conn, nvb_bytes path, nvb_handle **out, int64_t *size) noexcept
{
    clearOut(out);
    return guarded([conn, path, out, size]() {
        Backend *backend = backendOf(conn);
        if (!out)
            throw std::invalid_argument("no out-pointer");
        ReadHandle *raw = nullptr;
        const Result r = backend->openRead(toPath(path), &raw);
        std::unique_ptr<ReadHandle> opened(raw);
        if (!r.ok() || !opened)
            return r.ok() ? Result(Error::Internal, QStringLiteral("The backend returned no handle")) : r;
        auto handle = std::make_unique<nvb_handle>();
        handle->conn = conn;
        handle->handle = std::move(opened);
        if (size)
            *size = handle->handle->size();
        *out = handle.get();
        conn->handles.emplace(handle.get(), std::move(handle));
        return r;
    });
}

// Short read only at EOF.
nvb_error *handleRead(nvb_handle *h, int64_t offset, uint8_t *buf, size_t cap, size_t *len) noexcept
{
    if (len)
        *len = 0;
    return guarded([h, offset, buf, cap, len]() {
        ReadHandle *handle = readHandleOf(h);
        if (!buf && cap > 0)
            throw std::invalid_argument("no buffer");
        QByteArray data;
        const auto want = static_cast<qint64>(std::min<size_t>(cap, INT_MAX));
        const Result r = handle->read(offset, want, &data);
        if (!r.ok())
            return r;
        const auto n = std::min(static_cast<size_t>(data.size()), static_cast<size_t>(want));
        if (n > 0)
            std::memcpy(buf, data.constData(), n);
        if (len)
            *len = n;
        return r;
    });
}

void handleReadAhead(nvb_handle *h, int64_t offset, int64_t bytes) noexcept
{
    guardedVoid([h, offset, bytes]() { readHandleOf(h)->readAhead(offset, bytes); });
}

// Always frees the handle, also when close() fails.
nvb_error *handleClose(nvb_handle *h) noexcept
{
    return guarded([h]() {
        if (!h)
            return Result::success();
        const Result r = h->handle ? h->handle->close() : Result::success();
        if (h->conn)
            h->conn->handles.erase(h);
        return r;
    });
}

}