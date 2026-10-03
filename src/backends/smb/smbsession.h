// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SMBSESSION_H
#define NETVFS_SMBSESSION_H

#include "smb2api.h"
#include "smbcallbacks.h"
#include "smbutil.h"

#include <QtCore/QByteArray>
#include <QtCore/QSet>
#include <QtCore/QString>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace NetVfs::Smb {

// One asynchronous libsmb2 request. Heap-allocated so that a request
// abandoned on cancel or timeout can complete later without touching freed
// memory: it then moves to its session's orphans and keeps its buffers. The
// completion state is filled in by the C callbacks of smbcallbacks.c.
struct Call : NetVfsSmbCompletion {
    Call() : NetVfsSmbCompletion {} {}

    // The callback data handed to libsmb2 together with a netvfs_smb_complete_* callback.
    NetVfsSmbCompletion *completion() { return this; }

    smb2_stat_64 st = {};
    struct smb2_statvfs vfs = {};   // "struct": a function has the same name
    QByteArray buffer;
};

// M-13 (amended for C-8 hand-over): libsmb2 contexts are not thread-safe,
// but not bound to a thread either (no thread-local state at the pinned
// commit). A backend, its contexts and its handles are therefore used by
// one thread at a time: every entry point holds the gate for the duration
// of the call; a second thread is refused while the first is inside, and a
// connection handed over while idle (Ops::copyAcross runs the source on a
// worker thread) is fine. Nested entries of the holding thread (upload()
// calling openWrite()) are allowed.
class ThreadGate
{
public:
    bool enter();
    void leave();
    bool heldHere() const { return m_owner.load() == std::this_thread::get_id(); }

private:
    std::atomic<std::thread::id> m_owner {};
    int m_depth = 0;                // touched only by the holder
};

class GateHold
{
public:
    explicit GateHold(ThreadGate *gate) : m_gate(gate), m_entered(gate->enter()) {}
    ~GateHold()
    {
        if (m_entered)
            m_gate->leave();
    }
    GateHold(const GateHold &) = delete;
    GateHold &operator=(const GateHold &) = delete;
    // The call may go on; otherwise it returns busy().
    bool entered() const { return m_entered; }
    static Result busy();
    // Runs `body` (which returns a Result) inside the gate, or answers busy().
    template <typename Body>
    static Result run(ThreadGate *gate, Body body)
    {
        const GateHold hold(gate);
        return hold.entered() ? body() : busy();
    }

private:
    ThreadGate *m_gate;
    bool m_entered;
};

// An open file on a session (ReadHandle, WriteHandle). The session tells it
// when the context goes away; the handle then hands its outstanding requests
// back (Session::abandon) and answers ConnectionLost from then on.
class SessionFile
{
public:
    virtual ~SessionFile() = default;
    virtual void invalidate() = 0;
};

// SPEC-smb, SPEC-v2 §6.2: one smb2_context, signed in to one share (or to
// IPC$ for the root of server mode, XM-2), used only from the backend's
// thread (M-13). Requests go through libsmb2's asynchronous API and a poll
// loop so that cancel() and timeouts can abandon a request that is stalled
// on the network (M-12, C-9).
class Session
{
public:
    enum class Wait { Cancellable, Drain };

    // How long closing a file after a cancel or failure may take before that
    // request is abandoned too, so that Canceled comes back within C-9's 2 s.
    static constexpr int DrainMs = 1000;
    // Margin over the library's own request timeout (M-7) before the poll
    // loop gives up on a request by itself.
    static constexpr int BackstopMs = 5000;

    Session(const QString &share, const std::atomic<bool> &cancel, int requestTimeoutMs, ThreadGate *gate);
    ~Session();
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    // Negotiate, session setup and tree connect with the profile's settings
    // (XM-1), then the dialect and guest checks. The password is dropped
    // from libsmb2's copy right after (SEC-5).
    Result signIn(const QByteArray &server, Profile profile, const QString &user, const QString &domain,
                  const QByteArray &secret);

    const QString &share() const { return m_share; }
    // For calls that complete locally (smb2_readdir, smb2_closedir).
    smb2_context *context() const { return m_ctx; }
    bool established() const { return m_ctx && m_stage == Stage::Established; }
    bool broken() const { return m_broken; }
    Result checkUsable() const;
    quint32 readChunk() const;      // M-11
    quint32 writeChunk() const;
    quint16 dialect() const;

    // Issues one request and waits for it. `start` is
    // int (smb2_context *, Call *) and issues the libsmb2 request.
    template <typename Starter>
    Result request(std::unique_ptr<Call> &call, Starter start, const QString &context, Wait wait = Wait::Cancellable)
    {
        if (Result r = begin(call.get(), start, context, wait); !r.ok())
            return r;
        return finish(call, context, wait);
    }
    // Pipelining (XM-6): issue without waiting, then finish() each in order.
    template <typename Starter>
    Result begin(Call *call, Starter start, const QString &context, Wait wait = Wait::Cancellable)
    {
        if (Result r = prepare(wait); !r.ok())
            return r;
        if (start(m_ctx, call) < 0)
            return startFailed(context);
        return Result::success();
    }
    // Waits for a request issued with begin() and classifies its outcome.
    // A canceled or timed-out request is abandoned (`call` becomes null).
    Result finish(std::unique_ptr<Call> &call, const QString &context, Wait wait = Wait::Cancellable);
    // Hands a request that is no longer waited for to the session, which
    // keeps it until it completes or the context is destroyed.
    void abandon(std::unique_ptr<Call> &call);

    // Queues a close for a file whose handle is going away, without waiting.
    void closeLater(smb2fh *fh);
    bool canceled() const { return m_cancel; }
    ThreadGate *gate() const { return m_gate; }

    void attach(SessionFile *file) { m_files.insert(file); }
    void detach(SessionFile *file) { m_files.remove(file); }
    bool hasFiles() const { return !m_files.isEmpty(); }

    // Graceful: tree disconnect within DrainMs, then the context goes.
    void close() noexcept;

    // LRU among share sessions (XM-2).
    quint64 lastUse() const { return m_lastUse; }
    void touch(quint64 clock) { m_lastUse = clock; }

private:
    Result prepare(Wait wait);
    Result startFailed(const QString &context) const;
    Result await(std::unique_ptr<Call> &call, Wait wait);
    void destroy() noexcept;

    QString m_share;
    const std::atomic<bool> &m_cancel;
    int m_requestTimeoutMs;
    ThreadGate *m_gate;
    smb2_context *m_ctx = nullptr;
    Stage m_stage = Stage::SessionSetup;
    bool m_broken = false;
    std::vector<std::unique_ptr<Call>> m_orphans;
    QSet<SessionFile *> m_files;
    quint64 m_lastUse = 0;
};

} // namespace NetVfs::Smb

#endif
