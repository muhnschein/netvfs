// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_STREAMING_H
#define NETVFS_BRIDGE_STREAMING_H

#include "args.h"
#include "runtime.h"
#include "types.h"

#include <atomic>
#include <functional>
#include <memory>

// Streamed signals (ListBatch, WalkBatch): batching per XB-17 and flow control
// per C-10.
namespace NetVfs::Bridge {

// Bytes of streamed signals not yet written to the socket. Workers wait while
// it is above the limit, so a consumer that does not read cannot make the
// bridge buffer a whole tree.
struct FlowControl {
    static constexpr qint64 LimitBytes = 4 << 20;
    std::atomic<qint64> posted { 0 };      // posted to the main thread, not yet sent
    std::atomic<qint64> outgoing { 0 };    // queued in libdbus
    // False if canceled while waiting.
    bool wait(const CancelToken *token) const;
};

// Rough wire size of an entry, for the 1 MiB batch limit.
qint64 wireSize(const Entry &entry);

// Collects items into batches of at most `maxItems` items or
// Limits::MaxListBatchBytes bytes and hands every full batch to `emit` on the
// worker thread (after waiting for flow control).
template <typename Item>
class Batcher
{
public:
    using Emit = std::function<void(const QVector<Item> &items, qint64 bytes)>;
    using Size = std::function<qint64(const Item &item)>;

    Batcher(int maxItems, Size size, Emit emitter, std::shared_ptr<FlowControl> flow, CancelTokenPtr token)
        : m_maxItems(maxItems), m_size(std::move(size)), m_emit(std::move(emitter)), m_flow(std::move(flow)),
          m_token(std::move(token))
    {
    }

    bool add(const Item &item)
    {
        const qint64 bytes = m_size(item);
        if (!m_items.isEmpty() && m_bytes + bytes > Limits::MaxListBatchBytes && !flush())
            return false;
        m_items.append(item);
        m_bytes += bytes;
        if (m_items.size() >= m_maxItems)
            return flush();
        return !m_token->isCanceled();
    }

    bool flush()
    {
        if (m_token->isCanceled())
            return false;
        if (m_items.isEmpty())
            return true;
        if (!m_flow->wait(m_token.get()))
            return false;
        m_flow->posted.fetch_add(m_bytes);
        m_emit(m_items, m_bytes);
        m_items.clear();
        m_bytes = 0;
        return true;
    }

private:
    int m_maxItems;
    Size m_size;
    Emit m_emit;
    std::shared_ptr<FlowControl> m_flow;
    CancelTokenPtr m_token;
    QVector<Item> m_items;
    qint64 m_bytes = 0;
};

// ListSink that streams through a Batcher; each backend batch is flushed so
// entries reach the consumer as the protocol produces them (XC-6).
class EntryBatcher : public ListSink
{
public:
    EntryBatcher(int maxEntries, Batcher<Entry>::Emit emitter, std::shared_ptr<FlowControl> flow, CancelTokenPtr token);
    bool entries(const QVector<Entry> &batch) override;
    bool flush() { return m_batcher.flush(); }

private:
    Batcher<Entry> m_batcher;
};

} // namespace NetVfs::Bridge

#endif
