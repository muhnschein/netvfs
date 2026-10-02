// SPDX-License-Identifier: LGPL-2.1-or-later
// Jobs: Upload, Download (XB-11), CopyAcross, RemoveTree, Walk (XB-10).
#include "session.h"

#include "bridgelog.h"
#include "bridgeserver.h"
#include "fdcheck.h"
#include "names.h"
#include "ops.h"
#include "protocol.h"
#include "serverparts.h"

#include <chrono>

namespace NetVfs::Bridge {

namespace {

constexpr qint64 ProgressIntervalMs = 250;   // XB-10: JobProgress at most 4 Hz

qint64 steadyMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// Progress of a job, sent at most every 250 ms (worker thread side).
class JobProgressSink : public Progress, public Ops::TreeProgress
{
public:
    JobProgressSink(const BridgeServer *server, quint64 sessionId, quint32 job, CancelTokenPtr token)
        : m_server(server), m_sessionId(sessionId), m_job(job), m_token(std::move(token))
    {
    }

    void update(qint64 done, qint64 total) override
    {
        const qint64 now = steadyMs();
        if (now - m_lastMs < ProgressIntervalMs)
            return;
        m_lastMs = now;
        const BridgeServer *server = m_server;
        const quint64 sessionId = m_sessionId;
        const quint32 job = m_job;
        server->mainQueue()->post([server, sessionId, job, done, total]() {
            if (Session *s = server->session(sessionId))
                s->jobProgress(job, done, total);
        });
    }

    bool canceled() const override { return m_token->isCanceled(); }

    bool removed(const QString &, bool, qint64 files, qint64 dirs) override
    {
        update(files + dirs, -1);
        return !canceled();
    }

private:
    const BridgeServer *m_server;
    quint64 m_sessionId;
    quint32 m_job;
    CancelTokenPtr m_token;
    qint64 m_lastMs = 0;
};

struct WalkItem {
    QString path;
    Entry entry;
};

qint64 walkItemSize(const WalkItem &item)
{
    return wireSize(item.entry) + 3 * item.path.size();
}

class WalkStreamer : public Ops::WalkVisitor
{
public:
    explicit WalkStreamer(Batcher<WalkItem> *batcher) : m_batcher(batcher) {}

    bool visit(const QString &path, const Entry &entry, int, bool *) override
    {
        return m_batcher->add(WalkItem { path, entry });
    }

    bool listFailed(const QString &, const Result &) override
    {
        return true;   // unreadable sub-folders are skipped, as a file browser expects
    }

private:
    Batcher<WalkItem> *m_batcher;
};

// What an Upload or Download needs on the worker thread.
struct TransferJob {
    const BridgeServer *server;
    quint64 sessionId;
    quint32 job;
    UnixFd fd;                 // the job holds it; closed when the job ends
    QString path;
    TransferOptions options;
    FdInfo info;
    bool upload;
};

UploadOptions uploadOptionsFor(const TransferOptions &t, qint64 length)
{
    UploadOptions options;
    options.write.disposition = t.disposition;
    const bool resume = t.disposition == WriteOptions::Resume;
    options.write.resumeOffset = resume ? t.offset : 0;
    options.write.createMode = t.createMode;
    if (length >= 0)
        options.write.expectedSize = resume ? t.offset + length : length;
    if (t.hasMtime)
        options.write.modified = QDateTime::fromMSecsSinceEpoch(t.mtimeMs, Qt::UTC);
    return options;
}

Result transferOnWorker(const TransferJob &transfer, Backend *backend, const TaskContext &task, QVariantMap *extra)
{
    const TransferOptions &t = transfer.options;
    const FdInfo &info = transfer.info;
    qint64 length = t.size;
    if (transfer.upload && !info.fifo && length < 0)
        length = std::max<qint64>(0, info.size - t.offset);
    FdDevice device(transfer.fd.fd(), info, info.fifo ? 0 : t.offset, length, &task.token->canceled);
    device.open((transfer.upload ? QIODevice::ReadOnly : QIODevice::WriteOnly) | QIODevice::Unbuffered);
    JobProgressSink progress(transfer.server, transfer.sessionId, transfer.job, task.token);
    Result r;
    if (transfer.upload) {
        r = backend->upload(&device, transfer.path, uploadOptionsFor(t, length), &progress);
    } else {
        DownloadOptions options;
        options.offset = t.offset;
        options.length = t.size;
        r = backend->download(transfer.path, &device, options, &progress);
    }
    extra->insert(QStringLiteral("bytes"), device.transferred());
    device.close();
    return r;
}

// WalkBatch of one batch (main thread).
void postWalkBatch(const BridgeServer *server, quint64 sessionId, quint32 job, const QVector<WalkItem> &items,
                   qint64 bytes)
{
    server->mainQueue()->post([server, sessionId, job, items, bytes]() {
        Session *s = server->session(sessionId);
        if (!s)
            return;
        s->sendSignal("WalkBatch", [job, items](WireWriter &w) {
            w.uint32(job).openArray("(ay(ayyyxxxxixxssqays))");
            for (const WalkItem &item : items) {
                w.openStruct().bytes(Names::encode(item.path));
                Protocol::writeEntry(w, item.entry);
                w.close();
            }
            w.close();
        }, bytes);
    });
}

// What a Walk needs on the worker thread.
struct WalkJob {
    const BridgeServer *server;
    quint64 sessionId;
    quint32 job;
    QString root;
    TreeOptions tree;
    std::shared_ptr<FlowControl> flow;
};

Result walkOnWorker(const WalkJob &walk, Backend *backend, const TaskContext &task, QVariantMap *extra)
{
    qint64 count = 0;
    Batcher<WalkItem> batcher(Limits::MaxListBatch, walkItemSize,
                              [&count, walk](const QVector<WalkItem> &items, qint64 bytes) {
        count += items.size();
        postWalkBatch(walk.server, walk.sessionId, walk.job, items, bytes);
    }, walk.flow, task.token);
    WalkStreamer visitor(&batcher);
    Ops::WalkOptions options;
    options.postOrder = walk.tree.postOrder;
    options.maxDepth = walk.tree.maxDepth;
    options.symlinks = walk.tree.followSymlinks ? Ops::SymlinkPolicy::Follow : Ops::SymlinkPolicy::Never;
    Result r = Ops::walk(backend, walk.root, &visitor, options);
    if (r.ok() && !batcher.flush())
        r = Result(Error::Canceled);
    extra->insert(QStringLiteral("entries"), count);
    return r;
}

// What a RemoveTree needs on the worker thread.
struct RemoveJob {
    const BridgeServer *server;
    quint64 sessionId;
    quint32 job;
    QString path;
};

Result removeTreeOnWorker(const RemoveJob &removal, Backend *backend, const TaskContext &task, QVariantMap *extra)
{
    JobProgressSink progress(removal.server, removal.sessionId, removal.job, task.token);
    Ops::TreeCounts counts;
    const Result r = Ops::removeTree(backend, removal.path, &progress, Ops::RemoveTreeOptions(), &counts);
    extra->insert(QStringLiteral("files"), counts.files);
    extra->insert(QStringLiteral("dirs"), counts.dirs);
    return r;
}

} // namespace

// Upload, Download, CopyAcross, RemoveTree and Walk.
class Session::Jobs
{
public:
    explicit Jobs(Session &session) : m_session(session) {}

    // Handles the calls of this area; false for any other method.
    bool dispatch(const Call &call, const SharedMessage &message) const;

private:
    using Handler = void (Jobs::*)(const Call &call, const SharedMessage &message) const;
    using JobWork = std::function<Result(Backend *backend, const TaskContext &context, QVariantMap *extra)>;

    void onUpload(const Call &call, const SharedMessage &message) const;
    void onDownload(const Call &call, const SharedMessage &message) const;
    void onCopyAcross(const Call &call, const SharedMessage &message) const;
    void onRemoveTree(const Call &call, const SharedMessage &message) const;
    void onWalk(const Call &call, const SharedMessage &message) const;
    void startTransfer(const Call &call, const SharedMessage &message, bool upload) const;
    // XB-11: the descriptor is checked before any network work.
    bool checkTransfer(const Call &call, const SharedMessage &message, bool upload, FdInfo *info, Pool **pool) const;
    // Takes a job slot and replies with the job id; false (and an error
    // reply) over the limit.
    bool startJob(const SharedMessage &message, quint32 *job, quint64 *op) const;
    void runJob(Pool *pool, Lane lane, quint32 job, quint64 op, const JobWork &work) const;

    Session &m_session;
};

bool Session::dispatchJobs(const Call &call, const SharedMessage &message)
{
    return Jobs(*this).dispatch(call, message);
}

bool Session::Jobs::dispatch(const Call &call, const SharedMessage &message) const
{
    static const QHash<int, Handler> handlers = {
        { static_cast<int>(Method::Upload), &Jobs::onUpload },
        { static_cast<int>(Method::Download), &Jobs::onDownload },
        { static_cast<int>(Method::CopyAcross), &Jobs::onCopyAcross },
        { static_cast<int>(Method::RemoveTree), &Jobs::onRemoveTree },
        { static_cast<int>(Method::Walk), &Jobs::onWalk },
    };
    const auto it = handlers.constFind(static_cast<int>(call.method));
    if (it == handlers.constEnd())
        return false;
    (this->*(it.value()))(call, message);
    return true;
}

bool Session::Jobs::startJob(const SharedMessage &message, quint32 *job, quint64 *op) const
{
    if (!m_session.m_server->quota()->acquireJob()) {
        m_session.replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many running jobs"),
                                             QString(), ConsumerLimits::RetryAfterMs));
        return false;
    }
    *job = m_session.m_nextPublicId++;
    *op = m_session.newOp(SharedMessage(), *job);
    const quint32 id = *job;
    m_session.reply(message, [id](WireWriter &w) { w.uint32(id); });
    return true;
}

void Session::Jobs::runJob(Pool *pool, Lane lane, quint32 job, quint64 op, const JobWork &work) const
{
    const BridgeServer *server = m_session.m_server;
    const quint64 sessionId = m_session.m_id;
    const TaskContext task = m_session.context(op);
    pool->submit(lane, task, [server, sessionId, job, task, work](Backend *backend, const Result &ready, Worker *) {
        QVariantMap extra;
        Result r = ready.ok() ? work(backend, task, &extra) : ready;
        if (!r.ok() && task.canceled())
            r = Result(Error::Canceled);   // a local write failing because of the cancel
        server->mainQueue()->post([server, sessionId, job, r, extra]() {
            server->quota()->releaseJob();
            if (Session *s = server->session(sessionId))
                s->finishJob(job, r, extra);
        });
        return r;
    });
}

void Session::jobProgress(quint32 job, qint64 done, qint64 total)
{
    if (!m_publicOps.contains(job))
        return;
    sendSignal("JobProgress", [job, done, total](WireWriter &w) { w.uint32(job).int64(done).int64(total); });
}

void Session::finishJob(quint32 job, const Result &result, const QVariantMap &extraIn)
{
    m_ops.remove(m_publicOps.take(job));
    QVariantMap extra = extraIn;
    if (!result.detail().isEmpty())
        extra.insert(QStringLiteral("detail"), result.detail());
    if (result.retryAfterMs() >= 0)
        extra.insert(QStringLiteral("retryAfterMs"), result.retryAfterMs());
    const QString error = result.ok() ? QString() : errorName(result.error());
    const QString text = result.message();
    sendSignal("JobFinished", [job, error, text, extra](WireWriter &w) {
        w.uint32(job).string(error).string(text).variantMap(extra);
    });
}

void Session::Jobs::onUpload(const Call &call, const SharedMessage &message) const
{
    startTransfer(call, message, true);
}

void Session::Jobs::onDownload(const Call &call, const SharedMessage &message) const
{
    startTransfer(call, message, false);
}

bool Session::Jobs::checkTransfer(const Call &call, const SharedMessage &message, bool upload, FdInfo *info,
                                  Pool **pool) const
{
    if (const Result checked = checkTransferFd(call.fd.fd(), upload ? FdAccess::Read : FdAccess::Write, info);
        !checked.ok()) {
        qCWarning(lcNetVfsBridge).noquote() << m_session.m_server->tag() << "Refused a file descriptor:"
                                            << checked.message();
        m_session.replyError(message, checked);
        return false;
    }
    *pool = m_session.poolFor(call.loc, message);
    if (!*pool)
        return false;
    if (!upload)
        return true;
    const Result r = checkUploadLength(*info, call.transfer.size, (*pool)->spec().provider);
    if (!r.ok())
        m_session.replyError(message, r);
    return r.ok();
}

// XB-11: regular files are read and written at explicit offsets, FIFOs
// sequentially.
void Session::Jobs::startTransfer(const Call &call, const SharedMessage &message, bool upload) const
{
    FdInfo info;
    Pool *pool = nullptr;
    if (!checkTransfer(call, message, upload, &info, &pool))
        return;
    quint32 job = 0;
    quint64 op = 0;
    if (!startJob(message, &job, &op))
        return;
    const TransferJob transfer { m_session.m_server, m_session.m_id, job, call.fd, call.path, call.transfer, info,
                                 upload };
    runJob(pool, call.lane, job, op, [transfer](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        return transferOnWorker(transfer, backend, task, extra);
    });
}

void Session::Jobs::onRemoveTree(const Call &call, const SharedMessage &message) const
{
    Pool *pool = m_session.poolFor(call.loc, message);
    quint32 job = 0;
    quint64 op = 0;
    if (!pool || !startJob(message, &job, &op))
        return;
    const RemoveJob removal { m_session.m_server, m_session.m_id, job, call.path };
    runJob(pool, call.lane, job, op, [removal](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        return removeTreeOnWorker(removal, backend, task, extra);
    });
}

void Session::Jobs::onWalk(const Call &call, const SharedMessage &message) const
{
    Pool *pool = m_session.poolFor(call.loc, message);
    quint32 job = 0;
    quint64 op = 0;
    if (!pool || !startJob(message, &job, &op))
        return;
    const WalkJob walk { m_session.m_server, m_session.m_id, job, call.path, call.tree, m_session.m_flow };
    runJob(pool, call.lane, job, op, [walk](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        return walkOnWorker(walk, backend, task, extra);
    });
}

void Session::Jobs::onCopyAcross(const Call &call, const SharedMessage &message) const
{
    const Pool *source = m_session.poolFor(call.loc, message);
    if (!source)
        return;
    const Pool *destination = m_session.poolFor(call.loc2, message);
    if (!destination)
        return;
    quint32 job = 0;
    quint64 op = 0;
    if (!startJob(message, &job, &op))
        return;
    Ops::CopyAcrossOptions options;
    options.recursive = call.tree.recursive;
    options.mode = call.tree.replace ? RenameMode::Replace : RenameMode::NoReplace;
    const BridgeServer *server = m_session.m_server;
    const quint64 sessionId = m_session.m_id;
    const TaskContext task = m_session.context(op);
    const QString from = call.path;
    const QString to = call.path2;
    // Two connections at once on a thread of its own (Ops::copyAcross needs
    // both backends owned by the calling thread).
    const CopyJobs::Body body = [server, sessionId, job, task, from, to, options](Backend *src, Backend *dst,
                                                                              QVariantMap *) {
        JobProgressSink progress(server, sessionId, job, task.token);
        return Ops::copyAcross(src, from, dst, to, options, &progress);
    };
    const CopyJobs::Done done = [server, sessionId, job](const Result &r, const QVariantMap &extra) {
        server->quota()->releaseJob();
        if (Session *s = server->session(sessionId))
            s->finishJob(job, r, extra);
    };
    server->copyJobs()->start(source->spec(), destination->spec(), task, body, done);
}

} // namespace NetVfs::Bridge
