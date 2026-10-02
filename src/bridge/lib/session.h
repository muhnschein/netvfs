// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_SESSION_H
#define NETVFS_BRIDGE_SESSION_H

#include "args.h"
#include "pool.h"
#include "streaming.h"
#include "wireconnection.h"

#include <QtCore/QHash>
#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <QtCore/QTimer>

#include <functional>

namespace NetVfs {
namespace Bridge {

class BridgeServer;

// One consumer connection (main thread): dispatches calls (XB-10), tracks its
// requests, handles and jobs, and cancels all of them when it goes away
// (XB-13).
class Session : public QObject
{
    Q_OBJECT
public:
    using Writer = std::function<void(WireWriter &writer)>;
    // Runs on a worker thread; fills `reply` with the return values.
    using Work = std::function<Result(Backend *backend, Writer *reply)>;
    // Replaces the default reply of a request.
    using Completion = std::function<void(const Result &result, const Writer &writer)>;

    Session(quint64 id, WireConnection *connection, BridgeServer *server);
    ~Session() override;

    quint64 id() const { return m_id; }
    bool helloDone() const { return m_hello; }
    std::shared_ptr<FlowControl> flow() const { return m_flow; }

    // Main thread, from the MainQueue.
    void finishRequest(quint64 op, const Result &result, const Writer &writer);
    void sendSignal(const char *member, const Writer &writer, qint64 flowBytes = 0);
    void jobProgress(quint32 job, qint64 done, qint64 total);
    void finishJob(quint32 job, const Result &result, const QVariantMap &extra);
    void finishList(quint32 request, const Result &result);
    void handleOpened(quint64 op, const QString &loc, Worker *worker, quint32 workerHandle, qint64 size,
                      const Result &result);

    // Closes the connection: revocation (XB-6).
    void closeConnection();
    // Cancels everything in flight and closes the handles (XB-13).
    void cancelAll();

Q_SIGNALS:
    void finished(quint64 id);

private:
    struct Op {
        SharedMessage message;         // null for streams and jobs (replied at once)
        CancelTokenPtr token;
        quint32 publicId = 0;          // List request or job id, 0 if none
        Completion completion;
    };
    struct HandleRef {
        QString loc;
        Worker *worker = nullptr;      // verified through the pool before each use
        quint32 workerHandle = 0;
    };

    using Handler = void (Session::*)(const Call &call, const SharedMessage &message);

    void onMessage(DBusMessage *message);
    void dispatch(Call &call, const SharedMessage &message);
    static Handler handlerFor(Method method);

    void replyError(const SharedMessage &message, const Result &result, bool fromValidation = false);
    void reply(const SharedMessage &message, const Writer &writer = Writer());

    quint64 newOp(const SharedMessage &message, quint32 publicId);
    TaskContext context(quint64 op) const;
    bool acquireRequest(const SharedMessage &message);
    Pool *poolFor(const QString &loc, const SharedMessage &message);
    // Request/reply on a pooled connection; the request slot is taken here
    // and released when the work is done (even if the session is gone).
    void run(const Call &call, const SharedMessage &message, const Work &work,
             const Completion &completion = Completion());
    void runOnPool(Pool *pool, Lane lane, const SharedMessage &message, const Work &work,
                   const Completion &completion);
    bool resolveHandle(quint32 handle, const SharedMessage &message, HandleRef *out);

    // Session, locations, questions, handoff (session.cpp)
    void onHello(const Call &call, const SharedMessage &message);
    void onGetConsent(const Call &call, const SharedMessage &message);
    void onRequestConsent(const Call &call, const SharedMessage &message);
    void onListLocations(const Call &call, const SharedMessage &message);
    void onCapabilities(const Call &call, const SharedMessage &message);
    void onDisconnect(const Call &call, const SharedMessage &message);
    void onConnectAdHoc(Call &call, const SharedMessage &message);    // moves the secret out
    void connectAdHoc(const LocationSpec &spec, const SharedMessage &message);
    void onForgetAdHoc(const Call &call, const SharedMessage &message);
    void onDiscover(const Call &call, const SharedMessage &message);
    void onCancel(const Call &call, const SharedMessage &message);
    void onAnswer(Call &call, const SharedMessage &message);          // moves the answers out
    void onOpenAccountSettings(const Call &call, const SharedMessage &message);
    void onAddAccount(const Call &call, const SharedMessage &message);
    // Files (sessionfiles.cpp)
    void onList(const Call &call, const SharedMessage &message);
    void onStat(const Call &call, const SharedMessage &message);
    void onReadLink(const Call &call, const SharedMessage &message);
    void onSpaceInfo(const Call &call, const SharedMessage &message);
    void onChecksum(const Call &call, const SharedMessage &message);
    void onMakeDir(const Call &call, const SharedMessage &message);
    void onRemoveFile(const Call &call, const SharedMessage &message);
    void onRemoveDir(const Call &call, const SharedMessage &message);
    void onRename(const Call &call, const SharedMessage &message);
    void onSetAttributes(const Call &call, const SharedMessage &message);
    void onMakeSymlink(const Call &call, const SharedMessage &message);
    void onMakeHardlink(const Call &call, const SharedMessage &message);
    void onServerCopy(const Call &call, const SharedMessage &message);
    void onOpenRead(const Call &call, const SharedMessage &message);
    void onRead(const Call &call, const SharedMessage &message);
    void onReadAhead(const Call &call, const SharedMessage &message);
    void onClose(const Call &call, const SharedMessage &message);
    // Jobs (sessionjobs.cpp)
    void onUpload(const Call &call, const SharedMessage &message);
    void onDownload(const Call &call, const SharedMessage &message);
    void onCopyAcross(const Call &call, const SharedMessage &message);
    void onRemoveTree(const Call &call, const SharedMessage &message);
    void onWalk(const Call &call, const SharedMessage &message);
    void startTransfer(const Call &call, const SharedMessage &message, bool upload);
    // Takes a job slot and replies with the job id; false (and an error
    // reply) over the limit.
    bool startJob(const SharedMessage &message, quint32 *job, quint64 *op);
    using JobWork = std::function<Result(Backend *backend, const TaskContext &context, QVariantMap *extra)>;
    void runJob(Pool *pool, Lane lane, quint32 job, quint64 op, const JobWork &work);

    quint64 m_id;
    QPointer<WireConnection> m_connection;
    BridgeServer *m_server;
    std::shared_ptr<FlowControl> m_flow;
    QTimer m_flowTimer;
    bool m_hello = false;
    bool m_discovering = false;
    bool m_canceled = false;
    quint64 m_nextOp = 1;
    quint32 m_nextPublicId = 1;
    quint32 m_nextHandle = 1;
    QHash<quint64, Op> m_ops;
    QHash<quint32, quint64> m_publicOps;      // List request / job id -> op
    QHash<quint32, HandleRef> m_handles;
    QHash<quint32, qint64> m_jobProgressMs;   // last JobProgress per job (XB-10: <= 4 Hz)
};

} // namespace Bridge
} // namespace NetVfs

#endif
