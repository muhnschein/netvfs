// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_RSHOOKS_H
#define NETVFS_RSHOOKS_H

#include "netvfs_rs.h"
#include "error.h"
#include "types.h"

QT_BEGIN_NAMESPACE
class QIODevice;
QT_END_NAMESPACE

namespace NetVfs::Rs {

// The callbacks of one table call, each over the C++ object the Backend
// call was given. They run on the calling thread before the call returns
// (S3), and nothing they throw crosses into Rust (S5): a throw ends the
// callback as a refusal (stop, decline, -1) and result() turns the call's
// result into Internal.
class Hooks
{
public:
    explicit Hooks(const nvr_table *table) : m_table(table) {}
    Hooks(const Hooks &) = delete;
    Hooks &operator=(const Hooks &) = delete;

    // XC-6: batches go to `sink`; its false stops the listing.
    nvb_list_sink_fn list(ListSink *sink);
    // XC-15: questions go to `prompter`; nullptr for none.
    const nvr_prompter *prompter(AuthPrompter *prompter);
    // XC-14: nullptr for none.
    const nvb_progress *progress(Progress *progress);
    // Upload reads `device` in order, download writes it in order.
    const nvb_io *source(QIODevice *device);
    const nvb_io *sink(QIODevice *device);

    // `call`, or Internal when a callback threw.
    Result result(const Result &call) const;

private:
    template <typename T, typename Body>
    T guard(T refusal, const Body &body) noexcept;

    static int listBatch(void *ctx, const nvb_entry *entries, size_t n) noexcept;
    static int prompt(void *ctx, nvb_bytes name, nvb_bytes instruction, const nvb_prompt *prompts, size_t n,
                      nvb_reply *reply) noexcept;
    static void progressUpdate(void *ctx, int64_t done, int64_t total) noexcept;
    static int progressCanceled(void *ctx) noexcept;
    static int64_t readSource(void *ctx, int64_t pos, uint8_t *buf, size_t cap) noexcept;
    static int64_t writeSink(void *ctx, int64_t pos, const uint8_t *buf, size_t len) noexcept;

    const nvr_table *m_table;
    ListSink *m_sink = nullptr;
    AuthPrompter *m_prompter = nullptr;
    Progress *m_progressSink = nullptr;
    QIODevice *m_device = nullptr;
    nvr_prompter m_promptHook {};
    nvb_progress m_progressHook {};
    nvb_io m_io {};
    bool m_thrown = false;
};

} // namespace NetVfs::Rs

#endif
