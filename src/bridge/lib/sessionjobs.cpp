// SPDX-License-Identifier: LGPL-2.1-or-later
// Jobs: Upload, Download (XB-11), CopyAcross, RemoveTree, Walk (XB-10).
#include "session.h"

#include "bridgelog.h"
#include "bridgeserver.h"
#include "fdcheck.h"
#include "names.h"
#include "ops.h"
#include "protocol.h"

#include <chrono>

namespace NetVfs {
namespace Bridge {

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
    JobProgressSink(BridgeServer *server, quint64 sessionId, quint32 job, CancelTokenPtr token)
        : m_server(server), m_sessionId(sessionId), m_job(job), m_token(std::move(token))
    {
    }

    void update(qint64 done, qint64 total) override
    {
        const qint64 now = steadyMs();
        if (now - m_lastMs < ProgressIntervalMs)
            return;
        m_lastMs = now;
        BridgeServer *server = m_server;
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
    BridgeServer *m_server;
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

} // namespace

bool Session::startJob(const SharedMessage &message, quint32 *job, quint64 *op)
{
    if (!m_server->acquireJob()) {
        replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many running jobs"), QString(),
                                   ConsumerLimits::RetryAfterMs));
        return false;
    }
    *job = m_nextPublicId++;
    *op = newOp(SharedMessage(), *job);
    const quint32 id = *job;
    reply(message, [id](WireWriter &w) { w.uint32(id); });
    return true;
}

void Session::runJob(Pool *pool, Lane lane, quint32 job, quint64 op, const JobWork &work)
{
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const TaskContext task = context(op);
    pool->submit(lane, task, [server, sessionId, job, task, work](Backend *backend, const Result &ready, Worker *) {
        QVariantMap extra;
        Result r = ready.ok() ? work(backend, task, &extra) : ready;
        if (!r.ok() && task.canceled())
            r = Result(Error::Canceled);   // a local write failing because of the cancel
        server->mainQueue()->post([server, sessionId, job, r, extra]() {
            server->releaseJob();
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

void Session::onUpload(const Call &call, const SharedMessage &message)
{
    startTransfer(call, message, true);
}

void Session::onDownload(const Call &call, const SharedMessage &message)
{
    startTransfer(call, message, false);
}

// XB-11: the descriptor is checked before any network work; regular files
// are read and written at explicit offsets, FIFOs sequentially.
void Session::startTransfer(const Call &call, const SharedMessage &message, bool upload)
{
    FdInfo info;
    const Result checked = checkTransferFd(call.fd.fd(), upload ? FdAccess::Read : FdAccess::Write, &info);
    if (!checked.ok()) {
        qCWarning(lcNetVfsBridge).noquote() << m_server->tag() << "Refused a file descriptor:" << checked.message();
        replyError(message, checked);
        return;
    }
    Pool *pool = poolFor(call.loc, message);
    if (!pool)
        return;
    const TransferOptions t = call.transfer;
    if (upload) {
        if (const Result r = checkUploadLength(info, t.size, pool->spec().provider); !r.ok()) {
            replyError(message, r);
            return;
        }
    }
    quint32 job = 0;
    quint64 op = 0;
    if (!startJob(message, &job, &op))
        return;
    const UnixFd fd = call.fd;   // the job holds it; closed when the job ends
    const QString path = call.path;
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    runJob(pool, call.lane, job, op, [=](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        qint64 length = t.size;
        if (upload && !info.fifo && length < 0)
            length = std::max<qint64>(0, info.size - t.offset);
        FdDevice device(fd.fd(), info, info.fifo ? 0 : t.offset, length, &task.token->canceled);
        device.open((upload ? QIODevice::ReadOnly : QIODevice::WriteOnly) | QIODevice::Unbuffered);
        JobProgressSink progress(server, sessionId, job, task.token);
        Result r;
        if (upload) {
            UploadOptions options;
            options.write.disposition = t.disposition;
            const bool resume = t.disposition == WriteOptions::Resume;
            options.write.resumeOffset = resume ? t.offset : 0;
            options.write.createMode = t.createMode;
            if (length >= 0)
                options.write.expectedSize = resume ? t.offset + length : length;
            if (t.hasMtime)
                options.write.modified = QDateTime::fromMSecsSinceEpoch(t.mtimeMs, Qt::UTC);
            r = backend->upload(&device, path, options, &progress);
        } else {
            DownloadOptions options;
            options.offset = t.offset;
            options.length = t.size;
            r = backend->download(path, &device, options, &progress);
        }
        extra->insert(QStringLiteral("bytes"), device.transferred());
        device.close();
        return r;
    });
}

void Session::onRemoveTree(const Call &call, const SharedMessage &message)
{
    Pool *pool = poolFor(call.loc, message);
    quint32 job = 0;
    quint64 op = 0;
    if (!pool || !startJob(message, &job, &op))
        return;
    const QString path = call.path;
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    runJob(pool, call.lane, job, op, [=](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        JobProgressSink progress(server, sessionId, job, task.token);
        Ops::TreeCounts counts;
        const Result r = Ops::removeTree(backend, path, &progress, Ops::RemoveTreeOptions(), &counts);
        extra->insert(QStringLiteral("files"), counts.files);
        extra->insert(QStringLiteral("dirs"), counts.dirs);
        return r;
    });
}

void Session::onWalk(const Call &call, const SharedMessage &message)
{
    Pool *pool = poolFor(call.loc, message);
    quint32 job = 0;
    quint64 op = 0;
    if (!pool || !startJob(message, &job, &op))
        return;
    const QString root = call.path;
    const TreeOptions tree = call.tree;
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const std::shared_ptr<FlowControl> flow = m_flow;
    runJob(pool, call.lane, job, op, [=](Backend *backend, const TaskContext &task, QVariantMap *extra) {
        qint64 count = 0;
        Batcher<WalkItem> batcher(Limits::MaxListBatch, walkItemSize,
                                  [&count, server, sessionId, job](const QVector<WalkItem> &items, qint64 bytes) {
            count += items.size();
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
        }, flow, task.token);
        WalkStreamer visitor(&batcher);
        Ops::WalkOptions options;
        options.postOrder = tree.postOrder;
        options.maxDepth = tree.maxDepth;
        options.symlinks = tree.followSymlinks ? Ops::SymlinkPolicy::Follow : Ops::SymlinkPolicy::Never;
        Result r = Ops::walk(backend, root, &visitor, options);
        if (r.ok() && !batcher.flush())
            r = Result(Error::Canceled);
        extra->insert(QStringLiteral("entries"), count);
        return r;
    });
}

void Session::onCopyAcross(const Call &call, const SharedMessage &message)
{
    Pool *source = poolFor(call.loc, message);
    if (!source)
        return;
    Pool *destination = poolFor(call.loc2, message);
    if (!destination)
        return;
    quint32 job = 0;
    quint64 op = 0;
    if (!startJob(message, &job, &op))
        return;
    Ops::CopyAcrossOptions options;
    options.recursive = call.tree.recursive;
    options.mode = call.tree.replace ? RenameMode::Replace : RenameMode::NoReplace;
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const TaskContext task = context(op);
    const QString from = call.path;
    const QString to = call.path2;
    // Two connections at once on a thread of its own (Ops::copyAcross needs
    // both backends owned by the calling thread).
    m_server->startCopyJob(source->spec(), destination->spec(), task,
                           [server, sessionId, job, task, from, to, options](Backend *src, Backend *dst,
                                                                           QVariantMap *extra) {
        Q_UNUSED(extra)
        JobProgressSink progress(server, sessionId, job, task.token);
        return Ops::copyAcross(src, from, dst, to, options, &progress);
    },
                           [server, sessionId, job](const Result &r, const QVariantMap &extra) {
        server->releaseJob();
        if (Session *s = server->session(sessionId))
            s->finishJob(job, r, extra);
    });
}

} // namespace Bridge
} // namespace NetVfs
