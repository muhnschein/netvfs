// SPDX-License-Identifier: LGPL-2.1-or-later
// Listing, metadata, namespace operations and read handles (XB-10).
#include "session.h"

#include "bridgeserver.h"
#include "names.h"
#include "protocol.h"
#include "serverparts.h"
#include "streaming.h"

namespace NetVfs::Bridge {

namespace {

Session::Writer noReply()
{
    return Session::Writer();
}

// What a listing needs on the worker thread.
struct ListJob {
    const BridgeServer *server;
    quint64 sessionId;
    quint32 request;
    QString dir;
    int batch;
    std::shared_ptr<FlowControl> flow;
    CancelTokenPtr token;
};

void postListBatch(const ListJob &job, const QVector<Entry> &entries, qint64 bytes)
{
    const BridgeServer *server = job.server;
    const quint64 sessionId = job.sessionId;
    const quint32 request = job.request;
    server->mainQueue()->post([server, sessionId, request, entries, bytes]() {
        if (Session *s = server->session(sessionId)) {
            s->sendSignal("ListBatch", [request, entries](WireWriter &w) {
                w.uint32(request).openArray(Protocol::EntrySignature);
                for (const Entry &e : entries)
                    Protocol::writeEntry(w, e);
                w.close();
            }, bytes);
        }
    });
}

Result listOnWorker(const ListJob &job, Backend *backend)
{
    EntryBatcher batcher(job.batch, [job](const QVector<Entry> &entries, qint64 bytes) {
        postListBatch(job, entries, bytes);
    }, job.flow, job.token);
    ListOptions options;
    options.batchSize = job.batch;
    Result r = backend->list(job.dir, &batcher, options);
    if (r.ok() && !batcher.flush())
        r = Result(Error::Canceled);
    return r;
}

void finishListLater(const ListJob &job, const Result &r)
{
    const BridgeServer *server = job.server;
    const quint64 sessionId = job.sessionId;
    const quint32 request = job.request;
    server->mainQueue()->post([server, sessionId, request, r]() {
        server->quota()->releaseRequest();
        if (Session *s = server->session(sessionId))
            s->finishList(request, r);
    });
}

// What OpenRead needs on the worker thread.
struct OpenJob {
    const BridgeServer *server;
    quint64 sessionId;
    quint64 op;
    QString loc;
    QString path;
};

// Opens the file and keeps the handle with its worker.
Result openOnWorker(const OpenJob &job, Backend *backend, Worker *worker, quint32 *handle, qint64 *size)
{
    ReadHandle *raw = nullptr;
    const Result r = backend->openRead(job.path, &raw);
    if (std::unique_ptr<ReadHandle> opened(raw); r.ok() && opened) {
        *size = opened->size();
        *handle = worker->addHandle(std::move(opened));
    }
    return r;
}

void openedLater(const OpenJob &job, Worker *worker, quint32 handle, qint64 size, const Result &r)
{
    const BridgeServer *server = job.server;
    const quint64 sessionId = job.sessionId;
    const quint64 op = job.op;
    const QString loc = job.loc;
    server->mainQueue()->post([server, sessionId, op, loc, worker, handle, size, r]() {
        server->quota()->releaseRequest();
        if (Session *s = server->session(sessionId); s) {
            s->handleOpened(op, loc, worker, handle, size, r);
            return;
        }
        server->quota()->releaseHandle();
        server->locations()->closeWorkerHandle(loc, worker, handle);
    });
}

Result readOnWorker(const Worker *worker, quint32 workerHandle, qint64 offset, qint64 length, QByteArray *data)
{
    ReadHandle *h = worker->handle(workerHandle);
    if (!h)
        return Result(Error::ConnectionLost, QStringLiteral("The connection of this handle was closed"));
    return h->read(offset, length, data);
}

} // namespace

// Listing, metadata, namespace operations and read handles.
class Session::Files
{
public:
    explicit Files(Session &session) : m_session(session) {}

    // Handles the calls of this area; false for any other method.
    bool dispatch(const Call &call, const SharedMessage &message) const;

private:
    using Handler = void (Files::*)(const Call &call, const SharedMessage &message) const;

    void onList(const Call &call, const SharedMessage &message) const;
    void onStat(const Call &call, const SharedMessage &message) const;
    void onReadLink(const Call &call, const SharedMessage &message) const;
    void onSpaceInfo(const Call &call, const SharedMessage &message) const;
    void onChecksum(const Call &call, const SharedMessage &message) const;
    void onMakeDir(const Call &call, const SharedMessage &message) const;
    void onRemoveFile(const Call &call, const SharedMessage &message) const;
    void onRemoveDir(const Call &call, const SharedMessage &message) const;
    void onRename(const Call &call, const SharedMessage &message) const;
    void onSetAttributes(const Call &call, const SharedMessage &message) const;
    void onMakeSymlink(const Call &call, const SharedMessage &message) const;
    void onMakeHardlink(const Call &call, const SharedMessage &message) const;
    void onServerCopy(const Call &call, const SharedMessage &message) const;
    void onOpenRead(const Call &call, const SharedMessage &message) const;
    void onRead(const Call &call, const SharedMessage &message) const;
    void onReadAhead(const Call &call, const SharedMessage &message) const;
    void onClose(const Call &call, const SharedMessage &message) const;
    bool resolveHandle(quint32 handle, const SharedMessage &message, HandleRef *out) const;

    Session &m_session;
};

bool Session::dispatchFiles(const Call &call, const SharedMessage &message)
{
    return Files(*this).dispatch(call, message);
}

bool Session::Files::dispatch(const Call &call, const SharedMessage &message) const
{
    static const QHash<int, Handler> handlers = {
        { static_cast<int>(Method::List), &Files::onList },
        { static_cast<int>(Method::Stat), &Files::onStat },
        { static_cast<int>(Method::ReadLink), &Files::onReadLink },
        { static_cast<int>(Method::SpaceInfo), &Files::onSpaceInfo },
        { static_cast<int>(Method::Checksum), &Files::onChecksum },
        { static_cast<int>(Method::MakeDir), &Files::onMakeDir },
        { static_cast<int>(Method::RemoveFile), &Files::onRemoveFile },
        { static_cast<int>(Method::RemoveDir), &Files::onRemoveDir },
        { static_cast<int>(Method::Rename), &Files::onRename },
        { static_cast<int>(Method::SetAttributes), &Files::onSetAttributes },
        { static_cast<int>(Method::MakeSymlink), &Files::onMakeSymlink },
        { static_cast<int>(Method::MakeHardlink), &Files::onMakeHardlink },
        { static_cast<int>(Method::ServerCopy), &Files::onServerCopy },
        { static_cast<int>(Method::OpenRead), &Files::onOpenRead },
        { static_cast<int>(Method::Read), &Files::onRead },
        { static_cast<int>(Method::ReadAhead), &Files::onReadAhead },
        { static_cast<int>(Method::Close), &Files::onClose },
    };
    const auto it = handlers.constFind(static_cast<int>(call.method));
    if (it == handlers.constEnd())
        return false;
    (this->*(it.value()))(call, message);
    return true;
}

void Session::Files::onList(const Call &call, const SharedMessage &message) const
{
    Pool *pool = m_session.poolFor(call.loc, message);
    if (!pool || !m_session.acquireRequest(message))
        return;
    const quint32 request = m_session.m_nextPublicId++;
    const quint64 op = m_session.newOp(SharedMessage(), request);
    m_session.reply(message, [request](WireWriter &w) { w.uint32(request); });

    const TaskContext task = m_session.context(op);
    const ListJob job { m_session.m_server, m_session.m_id, request, call.path, static_cast<int>(call.number),
                        m_session.m_flow, task.token };
    pool->submit(call.lane, task, [job](Backend *backend, const Result &ready, Worker *) {
        const Result r = ready.ok() ? listOnWorker(job, backend) : ready;
        finishListLater(job, r);
        return r;
    });
}

void Session::finishList(quint32 request, const Result &result)
{
    const quint64 op = m_publicOps.take(request);
    m_ops.remove(op);
    const QString error = result.ok() ? QString() : errorName(result.error());
    const QString text = result.message();
    sendSignal("ListDone", [request, error, text](WireWriter &w) { w.uint32(request).string(error).string(text); });
}

void Session::Files::onStat(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    const bool follow = call.flag;
    m_session.run(call, message, [path, follow](Backend *backend, Writer *out) {
        Entry entry;
        const Result r = follow ? backend->stat(path, &entry) : backend->lstat(path, &entry);
        *out = [entry](WireWriter &w) { Protocol::writeEntry(w, entry); };
        return r;
    });
}

void Session::Files::onReadLink(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    m_session.run(call, message, [path](Backend *backend, Writer *out) {
        QString target;
        const Result r = backend->readLink(path, &target);
        const QByteArray bytes = Names::encode(target);
        *out = [bytes](WireWriter &w) { w.bytes(bytes); };
        return r;
    });
}

void Session::Files::onSpaceInfo(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    m_session.run(call, message, [path](Backend *backend, Writer *out) {
        SpaceInfo info;
        const Result r = backend->spaceInfo(path, &info);
        *out = [info](WireWriter &w) { w.int64(info.free).int64(info.total).int64(info.used); };
        return r;
    });
}

void Session::Files::onChecksum(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    const QString algorithm = call.text;
    m_session.run(call, message, [path, algorithm](Backend *backend, Writer *out) {
        QByteArray digest;
        const Result r = backend->checksum(path, algorithm, &digest);
        *out = [digest](WireWriter &w) { w.bytes(digest); };
        return r;
    });
}

void Session::Files::onMakeDir(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    const bool exclusive = call.flag;
    m_session.run(call, message, [path, exclusive](Backend *backend, Writer *out) {
        *out = noReply();
        return backend->makeDir(path, exclusive);
    });
}

void Session::Files::onRemoveFile(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    m_session.run(call, message, [path](Backend *backend, Writer *) { return backend->removeFile(path); });
}

void Session::Files::onRemoveDir(const Call &call, const SharedMessage &message) const
{
    const QString path = call.path;
    m_session.run(call, message, [path](Backend *backend, Writer *) { return backend->removeDir(path); });
}

void Session::Files::onRename(const Call &call, const SharedMessage &message) const
{
    const QString from = call.path;
    const QString to = call.path2;
    const RenameMode mode = call.flag ? RenameMode::Replace : RenameMode::NoReplace;
    m_session.run(call, message, [from, to, mode](Backend *backend, Writer *) {
        return backend->rename(from, to, mode);
    });
}

void Session::Files::onSetAttributes(const Call &call, const SharedMessage &message) const
{
    if (call.attributes.isEmpty()) {
        m_session.reply(message);   // nothing to change, no network round trip
        return;
    }
    const QString path = call.path;
    const AttributeChanges changes = call.attributes;
    m_session.run(call, message, [path, changes](Backend *backend, Writer *) {
        return backend->setAttributes(path, changes);
    });
}

void Session::Files::onMakeSymlink(const Call &call, const SharedMessage &message) const
{
    const QString target = call.linkTarget;
    const QString link = call.path2;
    m_session.run(call, message, [target, link](Backend *backend, Writer *) {
        return backend->makeSymlink(target, link);
    });
}

void Session::Files::onMakeHardlink(const Call &call, const SharedMessage &message) const
{
    const QString existing = call.path;
    const QString link = call.path2;
    m_session.run(call, message, [existing, link](Backend *backend, Writer *) {
        return backend->makeHardlink(existing, link);
    });
}

void Session::Files::onServerCopy(const Call &call, const SharedMessage &message) const
{
    const QString from = call.path;
    const QString to = call.path2;
    CopyOptions options;
    options.recursive = call.tree.recursive;
    options.mode = call.tree.replace ? RenameMode::Replace : RenameMode::NoReplace;
    m_session.run(call, message, [from, to, options](Backend *backend, Writer *) {
        return backend->copy(from, to, options);
    });
}

// ----------------------------------------------------------------- handles

void Session::Files::onOpenRead(const Call &call, const SharedMessage &message) const
{
    Pool *pool = m_session.poolFor(call.loc, message);
    if (!pool)
        return;
    ConsumerQuota *quota = m_session.m_server->quota();
    if (!quota->acquireHandle()) {
        m_session.replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many open files"),
                                             QString(), ConsumerLimits::RetryAfterMs));
        return;
    }
    if (!m_session.acquireRequest(message)) {
        quota->releaseHandle();
        return;
    }
    const quint64 op = m_session.newOp(message, 0);
    const OpenJob job { m_session.m_server, m_session.m_id, op, call.loc, call.path };
    pool->submit(call.lane, m_session.context(op), [job](Backend *backend, const Result &ready, Worker *worker) {
        Result r = ready;
        quint32 handle = 0;
        qint64 size = -1;
        if (r.ok())
            r = openOnWorker(job, backend, worker, &handle, &size);
        openedLater(job, worker, handle, size, r);
        return r;
    });
}

void Session::handleOpened(quint64 op, const QString &loc, Worker *worker, quint32 workerHandle, qint64 size,
                           const Result &result)
{
    const Op entry = m_ops.take(op);
    if (!result.ok()) {
        m_server->quota()->releaseHandle();
        replyError(entry.message, result);
        return;
    }
    const quint32 handle = m_nextHandle++;
    m_handles.insert(handle, HandleRef { loc, worker, workerHandle });
    reply(entry.message, [handle, size](WireWriter &w) { w.uint32(handle).int64(size); });
}

bool Session::Files::resolveHandle(quint32 handle, const SharedMessage &message, HandleRef *out) const
{
    const auto it = m_session.m_handles.constFind(handle);
    if (it == m_session.m_handles.constEnd()) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such handle")));
        return false;
    }
    if (const Pool *pool = m_session.m_server->locations()->existing(it->loc); !pool || !pool->owns(it->worker)) {
        m_session.replyError(message,
                             Result(Error::ConnectionLost, QStringLiteral("The connection of this handle was closed")));
        return false;
    }
    *out = it.value();
    return true;
}

void Session::Files::onRead(const Call &call, const SharedMessage &message) const
{
    HandleRef ref;
    if (!resolveHandle(call.number, message, &ref) || !m_session.acquireRequest(message))
        return;
    const quint64 op = m_session.newOp(message, 0);
    const BridgeServer *server = m_session.m_server;
    const quint64 sessionId = m_session.m_id;
    const quint32 workerHandle = ref.workerHandle;
    const qint64 offset = call.offset;
    const qint64 length = call.length;
    Pool::submitTo(ref.worker, m_session.context(op),
                   [server, sessionId, op, workerHandle, offset, length](Backend *, const Result &ready,
                                                                         const Worker *worker) {
        Result r = ready;
        QByteArray data;
        if (r.ok())
            r = readOnWorker(worker, workerHandle, offset, length, &data);
        const Writer writer = [data](WireWriter &w) { w.bytes(data); };
        server->mainQueue()->post([server, sessionId, op, r, writer]() {
            server->quota()->releaseRequest();
            if (Session *s = server->session(sessionId))
                s->finishRequest(op, r, writer);
        });
        return r;
    });
}

void Session::Files::onReadAhead(const Call &call, const SharedMessage &message) const
{
    HandleRef ref;
    if (!resolveHandle(call.number, message, &ref))
        return;
    const quint32 workerHandle = ref.workerHandle;
    const qint64 offset = call.offset;
    const qint64 bytes = call.length;
    Pool::submitTo(ref.worker, TaskContext(),
                   [workerHandle, offset, bytes](Backend *, const Result &ready, const Worker *worker) {
        if (ReadHandle *h = ready.ok() ? worker->handle(workerHandle) : nullptr; h)
            h->readAhead(offset, bytes);
        return Result::success();
    });
    m_session.reply(message);   // a hint: answered at once
}

void Session::Files::onClose(const Call &call, const SharedMessage &message) const
{
    const auto it = m_session.m_handles.find(call.number);
    if (it == m_session.m_handles.end()) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such handle")));
        return;
    }
    const HandleRef ref = it.value();
    m_session.m_handles.erase(it);
    m_session.m_server->quota()->releaseHandle();
    m_session.m_server->locations()->closeWorkerHandle(ref.loc, ref.worker, ref.workerHandle);
    m_session.reply(message);
}

} // namespace NetVfs::Bridge
