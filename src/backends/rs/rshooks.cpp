// SPDX-License-Identifier: LGPL-2.1-or-later
#include "rshooks.h"
#include "rsmarshal.h"
#include "secure.h"

#include <QtCore/QIODevice>

#include <vector>

namespace NetVfs::Rs {

namespace {

// Answers are wiped however the prompt ends.
struct Answers {
    QVector<QByteArray> items;

    Answers() = default;
    Answers(const Answers &) = delete;
    Answers &operator=(const Answers &) = delete;
    ~Answers()
    {
        for (QByteArray &answer : items)
            secureWipe(answer);
    }
};

Hooks *hooksOf(void *ctx)
{
    return static_cast<Hooks *>(ctx);
}

}
template <typename T, typename Body>
T Hooks::guard(T refusal, const Body &body) noexcept
{
    try {
        return body();
    } catch (...) {
        m_thrown = true;
        return refusal;
    }
}

Result Hooks::result(const Result &call) const
{
    if (!m_thrown)
        return call;
    return Result(Error::Internal, QStringLiteral("A callback of the Rust backend failed"),
                  call.ok() ? QString() : call.toString());
}

nvb_list_sink_fn Hooks::list(ListSink *sink)
{
    m_sink = sink;
    return &Hooks::listBatch;
}

int Hooks::listBatch(void *ctx, const nvb_entry *entries, size_t n) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    return hooks->guard(0, [hooks, entries, n]() {
        QVector<Entry> batch;
        batch.reserve(static_cast<int>(n));
        for (size_t i = 0; i < n; ++i)
            batch.append(entryOf(entries[i]));
        return hooks->m_sink->entries(batch) ? 1 : 0;
    });
}

const nvr_prompter *Hooks::prompter(AuthPrompter *prompter)
{
    if (!prompter)
        return nullptr;
    m_prompter = prompter;
    m_promptHook = nvr_prompter { this, &Hooks::prompt };
    return &m_promptHook;
}

int Hooks::prompt(void *ctx, nvb_bytes name, nvb_bytes instruction, const nvb_prompt *prompts, size_t n,
                  nvb_reply *reply) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    return hooks->guard(0, [hooks, name, instruction, prompts, n, reply]() {
        QVector<AuthPrompt> asked;
        for (size_t i = 0; i < n; ++i)
            asked.append(AuthPrompt { Ffi::toUtf8String(prompts[i].text), prompts[i].echo != 0 });
        Answers answers;
        if (!hooks->m_prompter->answer(Ffi::toUtf8String(name), Ffi::toUtf8String(instruction), asked,
                                       &answers.items))
            return 0;
        std::vector<nvb_bytes> views;
        for (const QByteArray &answer : answers.items)
            views.push_back(view(answer));
        hooks->m_table->reply_set(reply, views.data(), views.size());
        return 1;
    });
}

const nvb_progress *Hooks::progress(Progress *progress)
{
    if (!progress)
        return nullptr;
    m_progressSink = progress;
    m_progressHook = nvb_progress { this, &Hooks::progressUpdate, &Hooks::progressCanceled };
    return &m_progressHook;
}

void Hooks::progressUpdate(void *ctx, int64_t done, int64_t total) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    hooks->guard(0, [hooks, done, total]() {
        hooks->m_progressSink->update(done, total);
        return 0;
    });
}

int Hooks::progressCanceled(void *ctx) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    return hooks->guard(1, [hooks]() { return hooks->m_progressSink->canceled() ? 1 : 0; });
}

// Upload size is what the source holds from its position; a sequential source has none.
const nvb_io *Hooks::source(QIODevice *device)
{
    m_device = device;
    const bool sequential = device->isSequential();
    m_io = nvb_io { this, sequential ? uint8_t(1) : uint8_t(0),
                    sequential ? 0 : qMax<qint64>(0, device->size() - device->pos()), &Hooks::readSource, nullptr };
    return &m_io;
}

const nvb_io *Hooks::sink(QIODevice *device)
{
    m_device = device;
    m_io = nvb_io { this, device->isSequential() ? uint8_t(1) : uint8_t(0), 0, nullptr, &Hooks::writeSink };
    return &m_io;
}

int64_t Hooks::readSource(void *ctx, int64_t, uint8_t *buf, size_t cap) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    return hooks->guard<int64_t>(-1, [hooks, buf, cap]() {
        return hooks->m_device->read(reinterpret_cast<char *>(buf), static_cast<qint64>(cap));
    });
}

int64_t Hooks::writeSink(void *ctx, int64_t, const uint8_t *buf, size_t len) noexcept
{
    Hooks *hooks = hooksOf(ctx);
    return hooks->guard<int64_t>(-1, [hooks, buf, len]() {
        return hooks->m_device->write(reinterpret_cast<const char *>(buf), static_cast<qint64>(len));
    });
}

}