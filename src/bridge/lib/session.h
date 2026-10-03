// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BRIDGE_SESSION_H
#define NETVFS_BRIDGE_SESSION_H

// The moc of Qt 5.6 (Sailfish SDK) cannot parse C++17 nested namespaces; it
// does not need the headers that have them.
#ifndef Q_MOC_RUN
#include "args.h"
#include "pool.h"
#include "streaming.h"
#endif
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

    // The calls by area, defined with their code: the session, the locations,
    // the questions and the handoff (session.cpp); listing, metadata and read
    // handles (sessionfiles.cpp); jobs (sessionjobs.cpp).
    class Admin;
    class Files;
    class Jobs;

    void onMessage(DBusMessage *message);
    void dispatch(Call &call, const SharedMessage &message);
    // One area each; false for a method of another area.
    bool dispatchAdmin(Call &call, const SharedMessage &message);
    bool dispatchFiles(const Call &call, const SharedMessage &message);
    bool dispatchJobs(const Call &call, const SharedMessage &message);

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

    quint64 m_id;
    QPointer<WireConnection> m_connection;
    BridgeServer *m_server;
    std::shared_ptr<FlowControl> m_flow = std::make_shared<FlowControl>();
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
};

} // namespace Bridge
} // namespace NetVfs

#endif
