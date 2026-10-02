// SPDX-License-Identifier: LGPL-2.1-or-later
// Listing, metadata, namespace operations and read handles (XB-10).
#include "session.h"

#include "bridgeserver.h"
#include "names.h"
#include "protocol.h"
#include "streaming.h"

namespace NetVfs {
namespace Bridge {

namespace {

Session::Writer noReply()
{
    return Session::Writer();
}

} // namespace

void Session::onList(const Call &call, const SharedMessage &message)
{
    Pool *pool = poolFor(call.loc, message);
    if (!pool || !acquireRequest(message))
        return;
    const quint32 request = m_nextPublicId++;
    const quint64 op = newOp(SharedMessage(), request);
    reply(message, [request](WireWriter &w) { w.uint32(request); });

    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const QString dir = call.path;
    const int batch = static_cast<int>(call.number);
    const std::shared_ptr<FlowControl> flow = m_flow;
    const TaskContext task = context(op);
    const CancelTokenPtr token = task.token;
    pool->submit(call.lane, task, [=](Backend *backend, const Result &ready, Worker *) {
        Result r = ready;
        if (r.ok()) {
            EntryBatcher batcher(batch, [=](const QVector<Entry> &entries, qint64 bytes) {
                server->mainQueue()->post([=]() {
                    if (Session *s = server->session(sessionId)) {
                        s->sendSignal("ListBatch", [request, entries](WireWriter &w) {
                            w.uint32(request).openArray(Protocol::EntrySignature);
                            for (const Entry &e : entries)
                                Protocol::writeEntry(w, e);
                            w.close();
                        }, bytes);
                    }
                });
            }, flow, token);
            ListOptions options;
            options.batchSize = batch;
            r = backend->list(dir, &batcher, options);
            if (r.ok() && !batcher.flush())
                r = Result(Error::Canceled);
        }
        server->mainQueue()->post([server, sessionId, request, r]() {
            server->releaseRequest();
            if (Session *s = server->session(sessionId))
                s->finishList(request, r);
        });
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

void Session::onStat(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    const bool follow = call.flag;
    run(call, message, [path, follow](Backend *backend, Writer *out) {
        Entry entry;
        const Result r = follow ? backend->stat(path, &entry) : backend->lstat(path, &entry);
        *out = [entry](WireWriter &w) { Protocol::writeEntry(w, entry); };
        return r;
    });
}

void Session::onReadLink(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    run(call, message, [path](Backend *backend, Writer *out) {
        QString target;
        const Result r = backend->readLink(path, &target);
        const QByteArray bytes = Names::encode(target);
        *out = [bytes](WireWriter &w) { w.bytes(bytes); };
        return r;
    });
}

void Session::onSpaceInfo(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    run(call, message, [path](Backend *backend, Writer *out) {
        SpaceInfo info;
        const Result r = backend->spaceInfo(path, &info);
        *out = [info](WireWriter &w) { w.int64(info.free).int64(info.total).int64(info.used); };
        return r;
    });
}

void Session::onChecksum(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    const QString algorithm = call.text;
    run(call, message, [path, algorithm](Backend *backend, Writer *out) {
        QByteArray digest;
        const Result r = backend->checksum(path, algorithm, &digest);
        *out = [digest](WireWriter &w) { w.bytes(digest); };
        return r;
    });
}

void Session::onMakeDir(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    const bool exclusive = call.flag;
    run(call, message, [path, exclusive](Backend *backend, Writer *out) {
        *out = noReply();
        return backend->makeDir(path, exclusive);
    });
}

void Session::onRemoveFile(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    run(call, message, [path](Backend *backend, Writer *) { return backend->removeFile(path); });
}

void Session::onRemoveDir(const Call &call, const SharedMessage &message)
{
    const QString path = call.path;
    run(call, message, [path](Backend *backend, Writer *) { return backend->removeDir(path); });
}

void Session::onRename(const Call &call, const SharedMessage &message)
{
    const QString from = call.path;
    const QString to = call.path2;
    const RenameMode mode = call.flag ? RenameMode::Replace : RenameMode::NoReplace;
    run(call, message, [from, to, mode](Backend *backend, Writer *) { return backend->rename(from, to, mode); });
}

void Session::onSetAttributes(const Call &call, const SharedMessage &message)
{
    if (call.attributes.isEmpty()) {
        reply(message);   // nothing to change, no network round trip
        return;
    }
    const QString path = call.path;
    const AttributeChanges changes = call.attributes;
    run(call, message, [path, changes](Backend *backend, Writer *) { return backend->setAttributes(path, changes); });
}

void Session::onMakeSymlink(const Call &call, const SharedMessage &message)
{
    const QString target = call.linkTarget;
    const QString link = call.path2;
    run(call, message, [target, link](Backend *backend, Writer *) { return backend->makeSymlink(target, link); });
}

void Session::onMakeHardlink(const Call &call, const SharedMessage &message)
{
    const QString existing = call.path;
    const QString link = call.path2;
    run(call, message, [existing, link](Backend *backend, Writer *) { return backend->makeHardlink(existing, link); });
}

void Session::onServerCopy(const Call &call, const SharedMessage &message)
{
    const QString from = call.path;
    const QString to = call.path2;
    CopyOptions options;
    options.recursive = call.tree.recursive;
    options.mode = call.tree.replace ? RenameMode::Replace : RenameMode::NoReplace;
    run(call, message, [from, to, options](Backend *backend, Writer *) { return backend->copy(from, to, options); });
}

// ----------------------------------------------------------------- handles

void Session::onOpenRead(const Call &call, const SharedMessage &message)
{
    Pool *pool = poolFor(call.loc, message);
    if (!pool)
        return;
    if (!m_server->acquireHandle()) {
        replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many open files"), QString(),
                                   ConsumerLimits::RetryAfterMs));
        return;
    }
    if (!acquireRequest(message)) {
        m_server->releaseHandle();
        return;
    }
    const quint64 op = newOp(message, 0);
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const QString path = call.path;
    const QString loc = call.loc;
    pool->submit(call.lane, context(op), [=](Backend *backend, const Result &ready, Worker *worker) {
        Result r = ready;
        quint32 handle = 0;
        qint64 size = -1;
        if (r.ok()) {
            ReadHandle *h = nullptr;
            r = backend->openRead(path, &h);
            if (r.ok() && h) {
                size = h->size();
                handle = worker->addHandle(h);
            }
        }
        server->mainQueue()->post([=]() {
            server->releaseRequest();
            Session *s = server->session(sessionId);
            if (s) {
                s->handleOpened(op, loc, worker, handle, size, r);
                return;
            }
            server->releaseHandle();
            server->closeWorkerHandle(loc, worker, handle);
        });
        return r;
    });
}

void Session::handleOpened(quint64 op, const QString &loc, Worker *worker, quint32 workerHandle, qint64 size,
                           const Result &result)
{
    const Op entry = m_ops.take(op);
    if (!result.ok()) {
        m_server->releaseHandle();
        replyError(entry.message, result);
        return;
    }
    const quint32 handle = m_nextHandle++;
    m_handles.insert(handle, HandleRef { loc, worker, workerHandle });
    reply(entry.message, [handle, size](WireWriter &w) { w.uint32(handle).int64(size); });
}

bool Session::resolveHandle(quint32 handle, const SharedMessage &message, HandleRef *out)
{
    const auto it = m_handles.constFind(handle);
    if (it == m_handles.constEnd()) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such handle")));
        return false;
    }
    Pool *pool = m_server->existingPool(it->loc);
    if (!pool || !pool->owns(it->worker)) {
        replyError(message, Result(Error::ConnectionLost, QStringLiteral("The connection of this handle was closed")));
        return false;
    }
    *out = it.value();
    return true;
}

void Session::onRead(const Call &call, const SharedMessage &message)
{
    HandleRef ref;
    if (!resolveHandle(call.number, message, &ref) || !acquireRequest(message))
        return;
    const quint64 op = newOp(message, 0);
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    const quint32 workerHandle = ref.workerHandle;
    const qint64 offset = call.offset;
    const qint64 length = call.length;
    Pool::submitTo(ref.worker, context(op), [=](Backend *, const Result &ready, Worker *worker) {
        Result r = ready;
        QByteArray data;
        if (r.ok()) {
            ReadHandle *h = worker->handle(workerHandle);
            r = h ? h->read(offset, length, &data)
                  : Result(Error::ConnectionLost, QStringLiteral("The connection of this handle was closed"));
        }
        const Writer writer = [data](WireWriter &w) { w.bytes(data); };
        server->mainQueue()->post([server, sessionId, op, r, writer]() {
            server->releaseRequest();
            if (Session *s = server->session(sessionId))
                s->finishRequest(op, r, writer);
        });
        return r;
    });
}

void Session::onReadAhead(const Call &call, const SharedMessage &message)
{
    HandleRef ref;
    if (!resolveHandle(call.number, message, &ref))
        return;
    const quint32 workerHandle = ref.workerHandle;
    const qint64 offset = call.offset;
    const qint64 bytes = call.length;
    Pool::submitTo(ref.worker, TaskContext(), [=](Backend *, const Result &ready, Worker *worker) {
        ReadHandle *h = ready.ok() ? worker->handle(workerHandle) : nullptr;
        if (h)
            h->readAhead(offset, bytes);
        return Result::success();
    });
    reply(message);   // a hint: answered at once
}

void Session::onClose(const Call &call, const SharedMessage &message)
{
    const auto it = m_handles.find(call.number);
    if (it == m_handles.end()) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such handle")));
        return;
    }
    const HandleRef ref = it.value();
    m_handles.erase(it);
    m_server->releaseHandle();
    m_server->closeWorkerHandle(ref.loc, ref.worker, ref.workerHandle);
    reply(message);
}

} // namespace Bridge
} // namespace NetVfs
