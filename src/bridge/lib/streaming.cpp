// SPDX-License-Identifier: LGPL-2.1-or-later
#include "streaming.h"

#include <chrono>
#include <thread>

namespace NetVfs::Bridge {

namespace {
constexpr int FlowPollMs = 20;
constexpr qint64 EntryFixedBytes = 96;   // the fixed-size fields and alignment
} // namespace

bool FlowControl::wait(const CancelToken *token) const
{
    while (posted.load() + outgoing.load() > LimitBytes) {
        if (token && token->isCanceled())
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(FlowPollMs));
    }
    return !(token && token->isCanceled());
}

qint64 wireSize(const Entry &entry)
{
    // UTF-16 length times 3 bounds the UTF-8 size.
    return EntryFixedBytes + 3 * (entry.name.size() + entry.owner.size() + entry.group.size()
                                  + entry.contentType.size()) + entry.etag.size();
}

EntryBatcher::EntryBatcher(int maxEntries, Batcher<Entry>::Emit emitter, std::shared_ptr<FlowControl> flow,
                           CancelTokenPtr token)
    : m_batcher(maxEntries, wireSize, std::move(emitter), std::move(flow), std::move(token))
{
}

bool EntryBatcher::entries(const QVector<Entry> &batch)
{
    for (const Entry &entry : batch) {
        if (!m_batcher.add(entry))
            return false;
    }
    return m_batcher.flush();
}

} // namespace NetVfs::Bridge
