// SPDX-License-Identifier: LGPL-2.1-or-later
#include "smbsession.h"

#include "logging.h"

#include <QtCore/QElapsedTimer>

#include <algorithm>
#include <mutex>

#include <poll.h>

namespace NetVfs::Smb {

namespace {

const int PollSliceMs = 100;

// libsmb2 keeps every context in one process-wide list without a lock
// (lib/init.c, active_contexts), so creating and destroying contexts is
// serialised across all backends of the process.
std::mutex &contextListMutex()
{
    static std::mutex mutex;
    return mutex;
}

smb2_context *createContext()
{
    const std::scoped_lock lock(contextListMutex());
    return smb2_init_context();
}

void destroyContext(smb2_context *ctx)
{
    const std::scoped_lock lock(contextListMutex());
    smb2_destroy_context(ctx);
}

} // namespace

bool ThreadGate::enter()
{
    const std::thread::id self = std::this_thread::get_id();
    std::thread::id idle;
    if (m_owner.compare_exchange_strong(idle, self)) {
        m_depth = 1;
        return true;
    }
    if (idle != self)
        return false;           // M-13: another thread is inside
    ++m_depth;
    return true;
}

void ThreadGate::leave()
{
    if (--m_depth == 0)
        m_owner.store(std::thread::id());
}

Result GateHold::busy()
{
    return Result(Error::Internal, QStringLiteral("An SMB connection is used from one thread at a time"));
}

Session::Session(const QString &share, const std::atomic<bool> &cancel, int requestTimeoutMs, ThreadGate *gate)
    : m_share(share), m_cancel(cancel), m_requestTimeoutMs(requestTimeoutMs), m_gate(gate)
{
}

Session::~Session()
{
    destroy();
}

Result Session::signIn(const QByteArray &server, Profile profile, const QString &user, const QString &domain,
                       const QByteArray &secret)
{
    destroy();
    m_ctx = createContext();
    if (!m_ctx)
        return Result(Error::Internal, QStringLiteral("Cannot create an SMB context"));
    m_stage = Stage::SessionSetup;
    applyProfile(m_ctx, profile, user, domain, secret, m_requestTimeoutMs);

    const QByteArray shareName = encodeName(m_share);
    qCDebug(lcNetVfsSmb) << "Signing in to share" << m_share << "with profile" << profileName(profile);
    auto call = std::make_unique<Call>();
    Result r = request(call, [&server, &shareName](smb2_context *ctx, Call *c) {
        // The user is already set (applyProfile); passing it again here would
        // make libsmb2 consult NTLM_USER_FILE once more.
        return smb2_connect_share_async(ctx, server.constData(), shareName.constData(), nullptr,
                                        netvfs_smb_complete_plain, c->completion());
    }, QStringLiteral("Sign-in failed"));
    // SEC-5: drop libsmb2's copy of the password as soon as it is not needed.
    smb2_set_password(m_ctx, nullptr);

    // XM-1 guest mapping, M-1 defence in depth for the dialect.
    r = checkSession(m_ctx, profile, r);
    if (!r.ok()) {
        destroy();
        return r;
    }
    m_stage = Stage::Established;
    qCDebug(lcNetVfsSmb) << "Signed in, dialect" << dialectName(smb2_get_dialect(m_ctx));
    return r;
}

Result Session::checkUsable() const
{
    if (!m_ctx)
        return Result(Error::Internal, QStringLiteral("Not signed in"));
    if (!m_gate->heldHere())                             // M-13
        return GateHold::busy();
    if (m_broken)
        return connectionLost(Stage::Established);
    return Result::success();
}

quint32 Session::readChunk() const
{
    return chunkSize(m_ctx ? smb2_get_max_read_size(m_ctx) : 0);
}

quint32 Session::writeChunk() const
{
    return chunkSize(m_ctx ? smb2_get_max_write_size(m_ctx) : 0);
}

quint16 Session::dialect() const
{
    return m_ctx ? smb2_get_dialect(m_ctx) : 0;
}

Result Session::prepare(Wait wait)
{
    if (Result r = checkUsable(); !r.ok())
        return r;
    if (wait == Wait::Cancellable && m_cancel)
        return Result(Error::Canceled);
    auto completed = [](const std::unique_ptr<Call> &orphan) { return orphan->done != 0; };
    m_orphans.erase(std::remove_if(m_orphans.begin(), m_orphans.end(), completed), m_orphans.end());
    smb2_set_error(m_ctx, "");      // clears the NT status of an earlier request
    return Result::success();
}

Result Session::startFailed(const QString &context) const
{
    return Result(Error::Internal, context + QStringLiteral(": ") + QString::fromUtf8(smb2_get_error(m_ctx)));
}

Result Session::finish(std::unique_ptr<Call> &call, const QString &context, Wait wait)
{
    const Result r = await(call, wait);
    if (r.error() == Error::Canceled)
        return r;
    if (!r.ok())
        return Result(r.error(), context + QStringLiteral(": ") + r.message());
    if (call->status < 0)
        return errorForStatus(call->ntStatus, -call->status, m_stage, context);
    return r;
}

Result Session::await(std::unique_ptr<Call> &call, Wait wait)
{
    const qint64 limitMs = wait == Wait::Drain ? DrainMs : qint64(m_requestTimeoutMs) + BackstopMs;
    const SigPipeGuard guard;
    QElapsedTimer clock;
    clock.start();
    while (call->done == 0) {
        // M-12, C-9: a cancel abandons the request at once.
        if (wait == Wait::Cancellable && m_cancel) {
            abandon(call);
            return Result(Error::Canceled);
        }
        if (clock.elapsed() > limitMs) {
            abandon(call);
            m_broken = m_broken || wait == Wait::Cancellable;
            return Result(Error::Timeout, QStringLiteral("the server did not answer in time"));
        }
        if (m_broken) {
            abandon(call);
            return connectionLost(m_stage);
        }
        pollfd pfd = {};
        pfd.fd = smb2_get_fd(m_ctx);
        pfd.events = static_cast<short>(smb2_which_events(m_ctx));
        // Also called without events: libsmb2 expires timed-out requests there (M-7).
        if (const int rc = ::poll(&pfd, 1, PollSliceMs); smb2_service(m_ctx, rc > 0 ? pfd.revents : 0) >= 0)
            continue;
        m_broken = true;
        if (call->done == 0) {
            abandon(call);
            return connectionLost(m_stage);
        }
    }
    return Result::success();
}

void Session::abandon(std::unique_ptr<Call> &call)
{
    if (!call)
        return;
    call->orphaned = 1;
    if (call->done == 0)
        m_orphans.push_back(std::move(call));
    call.reset();
}

void Session::closeLater(smb2fh *fh)
{
    if (!m_ctx || !fh)
        return;
    auto call = std::make_unique<Call>();
    if (smb2_close_async(m_ctx, fh, netvfs_smb_complete_plain, call->completion()) == 0)
        abandon(call);
}

void Session::close() noexcept
{
    if (established() && !m_broken && m_gate->heldHere()) {
        auto call = std::make_unique<Call>();
        request(call, [](smb2_context *ctx, Call *c) {
            return smb2_disconnect_share_async(ctx, netvfs_smb_complete_plain, c->completion());
        }, QStringLiteral("disconnect"), Wait::Drain);
    }
    destroy();
}

void Session::destroy() noexcept
{
    // XC-13: files end with the connection. Each queues its close without
    // waiting and hands back its outstanding requests; libsmb2 completes
    // them, at the latest with a shutdown status in smb2_destroy_context().
    const QSet<SessionFile *> files = m_files;
    m_files.clear();
    for (SessionFile *file : files)
        file->invalidate();
    if (m_ctx) {
        // Pending requests complete here, so the orphans they refer to must
        // still exist.
        destroyContext(m_ctx);
        m_ctx = nullptr;
    }
    m_orphans.clear();
    m_broken = false;
    m_stage = Stage::SessionSetup;
}

} // namespace NetVfs::Smb
