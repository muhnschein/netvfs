// SPDX-License-Identifier: LGPL-2.1-or-later
#include "session.h"

#include "backendloader.h"
#include "bridgelog.h"
#include "bridgeserver.h"
#include "protocol.h"
#include "secure.h"
#include "url.h"

#include <dbus/dbus.h>

namespace NetVfs {
namespace Bridge {

namespace {

constexpr int FlowTimerMs = 50;

bool needsInsecureConsent(const ConnectionParams &params)
{
    const QString provider = params.provider;
    if (provider == QLatin1String("webdav"))
        return params.option(QStringLiteral("tls")) == QLatin1String("http");
    if (provider == QLatin1String("ftp"))
        return params.option(QStringLiteral("tls_mode")) == QLatin1String("none");
    if (provider == QLatin1String("smb")) {
        const QString profile = params.option(QStringLiteral("security_profile"));
        return profile == QLatin1String("legacy") || profile == QLatin1String("guest");
    }
    return false;
}

QString bytesOf(const char *s)
{
    return QString::fromUtf8(s ? s : "");
}

} // namespace

Session::Session(quint64 id, WireConnection *connection, BridgeServer *server)
    : m_id(id)
    , m_connection(connection)
    , m_server(server)
    , m_flow(std::make_shared<FlowControl>())
{
    connection->setParent(this);
    connection->setHandler([this](DBusMessage *message) { onMessage(message); });
    connect(connection, &WireConnection::disconnected, this, [this]() {
        cancelAll();
        emit finished(m_id);
    });
    m_flowTimer.setInterval(FlowTimerMs);
    connect(&m_flowTimer, &QTimer::timeout, this, [this]() {
        const qint64 outgoing = m_connection ? m_connection->outgoingBytes() : 0;
        m_flow->outgoing.store(outgoing);
        if (outgoing == 0)
            m_flowTimer.stop();
    });
}

Session::~Session()
{
    cancelAll();
}

// ------------------------------------------------------------- dispatching

void Session::onMessage(DBusMessage *raw)
{
    if (dbus_message_get_type(raw) != DBUS_MESSAGE_TYPE_METHOD_CALL)
        return;
    const SharedMessage message = shareMessage(raw);
    const QString path = bytesOf(dbus_message_get_path(raw));
    const QString interface = bytesOf(dbus_message_get_interface(raw));
    const QString member = bytesOf(dbus_message_get_member(raw));
    if (path != QLatin1String(Protocol::ObjectPath)) {
        replyError(message, Result(Error::Unsupported, QStringLiteral("No such object")), true);
        return;
    }
    if (member == QLatin1String("Introspect")
            && (interface.isEmpty() || interface == QLatin1String(DBUS_INTERFACE_INTROSPECTABLE))) {
        const QString xml = Protocol::introspectionXml();
        reply(message, [xml](WireWriter &w) { w.string(xml); });
        return;
    }
    if (!interface.isEmpty() && interface != QLatin1String(Protocol::Interface)) {
        replyError(message, Result(Error::Unsupported, QStringLiteral("No such interface")), true);
        return;
    }
    QVariantList args;
    Call call;
    Result r = decodeArguments(raw, &args);
    if (r.ok())
        r = validateCall(member, bytesOf(dbus_message_get_signature(raw)), &args, &call);
    args.clear();
    if (!r.ok()) {
        wipeSecrets(&call);
        qCDebug(lcNetVfsBridge).noquote() << m_server->tag() << "Refused" << member << r.toString();
        replyError(message, r, true);
        return;
    }
    if (!m_hello && call.method != Method::Hello) {
        wipeSecrets(&call);
        replyError(message, Result(Error::ProtocolError, QStringLiteral("Hello must be the first call")));
        return;
    }
    const MethodInfo *info = findMethod(member);
    if (info && info->needsConsent && m_server->consent() != Consent::Granted) {
        wipeSecrets(&call);
        replyError(message, Result(Error::PermissionDenied,
                                   QStringLiteral("The user has not allowed this app to use network locations")));
        return;
    }
    dispatch(call, message);
    wipeSecrets(&call);
}

Session::Handler Session::handlerFor(Method method)
{
    static const QHash<int, Handler> handlers = {
        { int(Method::Hello), &Session::onHello },
        { int(Method::GetConsent), &Session::onGetConsent },
        { int(Method::RequestConsent), &Session::onRequestConsent },
        { int(Method::ListLocations), &Session::onListLocations },
        { int(Method::Capabilities), &Session::onCapabilities },
        { int(Method::Disconnect), &Session::onDisconnect },
        { int(Method::ForgetAdHoc), &Session::onForgetAdHoc },
        { int(Method::Discover), &Session::onDiscover },
        { int(Method::List), &Session::onList },
        { int(Method::Stat), &Session::onStat },
        { int(Method::ReadLink), &Session::onReadLink },
        { int(Method::SpaceInfo), &Session::onSpaceInfo },
        { int(Method::Checksum), &Session::onChecksum },
        { int(Method::MakeDir), &Session::onMakeDir },
        { int(Method::RemoveFile), &Session::onRemoveFile },
        { int(Method::RemoveDir), &Session::onRemoveDir },
        { int(Method::Rename), &Session::onRename },
        { int(Method::SetAttributes), &Session::onSetAttributes },
        { int(Method::MakeSymlink), &Session::onMakeSymlink },
        { int(Method::MakeHardlink), &Session::onMakeHardlink },
        { int(Method::ServerCopy), &Session::onServerCopy },
        { int(Method::OpenRead), &Session::onOpenRead },
        { int(Method::Read), &Session::onRead },
        { int(Method::ReadAhead), &Session::onReadAhead },
        { int(Method::Close), &Session::onClose },
        { int(Method::Upload), &Session::onUpload },
        { int(Method::Download), &Session::onDownload },
        { int(Method::CopyAcross), &Session::onCopyAcross },
        { int(Method::RemoveTree), &Session::onRemoveTree },
        { int(Method::Walk), &Session::onWalk },
        { int(Method::Cancel), &Session::onCancel },
        { int(Method::OpenAccountSettings), &Session::onOpenAccountSettings },
        { int(Method::AddAccount), &Session::onAddAccount },
    };
    return handlers.value(int(method), nullptr);
}

void Session::dispatch(Call &call, const SharedMessage &message)
{
    if (call.method == Method::ConnectAdHoc) {
        onConnectAdHoc(call, message);
        return;
    }
    if (call.method == Method::Answer) {
        onAnswer(call, message);
        return;
    }
    const Handler handler = handlerFor(call.method);
    if (handler)
        (this->*handler)(call, message);
    else
        replyError(message, Result(Error::Unsupported, QStringLiteral("No such method")), true);
}

// --------------------------------------------------------------- replies

void Session::reply(const SharedMessage &message, const Writer &writer)
{
    if (!m_connection || !message || dbus_message_get_no_reply(message.get()))
        return;
    MessagePtr out = Protocol::methodReturn(message.get());
    if (!out)
        return;
    if (writer) {
        WireWriter w(out.get());
        writer(w);
        if (!w.ok()) {
            replyError(message, Result(Error::Internal, QStringLiteral("Cannot encode the reply")));
            return;
        }
    }
    m_connection->send(std::move(out));
}

void Session::replyError(const SharedMessage &message, const Result &result, bool fromValidation)
{
    if (!m_connection || !message || dbus_message_get_no_reply(message.get()))
        return;
    m_connection->send(Protocol::errorReply(message.get(), Protocol::errorNameFor(result, fromValidation), result));
}

void Session::sendSignal(const char *member, const Writer &writer, qint64 flowBytes)
{
    m_flow->posted.fetch_sub(flowBytes);
    if (!m_connection || m_canceled)
        return;
    MessagePtr out = Protocol::signal(member);
    if (!out)
        return;
    WireWriter w(out.get());
    if (writer)
        writer(w);
    if (!w.ok()) {
        qCWarning(lcNetVfsBridge).noquote() << m_server->tag() << "Cannot encode signal" << member;
        return;
    }
    m_connection->send(std::move(out));
    if (flowBytes > 0) {
        m_flow->outgoing.store(m_connection->outgoingBytes());
        if (!m_flowTimer.isActive())
            m_flowTimer.start();
    }
}

// ----------------------------------------------------------- bookkeeping

quint64 Session::newOp(const SharedMessage &message, quint32 publicId)
{
    const quint64 op = m_nextOp++;
    Op entry;
    entry.message = message;
    entry.token = std::make_shared<CancelToken>();
    entry.publicId = publicId;
    m_ops.insert(op, entry);
    if (publicId)
        m_publicOps.insert(publicId, op);
    return op;
}

TaskContext Session::context(quint64 op) const
{
    TaskContext context;
    context.sessionId = m_id;
    context.token = m_ops.value(op).token;
    return context;
}

bool Session::acquireRequest(const SharedMessage &message)
{
    if (m_server->acquireRequest())
        return true;
    replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many requests"), QString(),
                               ConsumerLimits::RetryAfterMs));
    return false;
}

Pool *Session::poolFor(const QString &loc, const SharedMessage &message)
{
    Result error;
    Pool *pool = m_server->pool(loc, &error);
    if (!pool)
        replyError(message, error);
    return pool;
}

void Session::run(const Call &call, const SharedMessage &message, const Work &work, const Completion &completion)
{
    Pool *pool = poolFor(call.loc, message);
    if (pool)
        runOnPool(pool, call.lane, message, work, completion);
}

void Session::runOnPool(Pool *pool, Lane lane, const SharedMessage &message, const Work &work,
                       const Completion &completion)
{
    if (!acquireRequest(message))
        return;
    const quint64 op = newOp(message, 0);
    m_ops[op].completion = completion;
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    pool->submit(lane, context(op), [server, sessionId, op, work](Backend *backend, const Result &ready, Worker *) {
        Writer writer;
        const Result r = ready.ok() ? work(backend, &writer) : ready;
        server->mainQueue()->post([server, sessionId, op, r, writer]() {
            server->releaseRequest();
            if (Session *s = server->session(sessionId))
                s->finishRequest(op, r, writer);
        });
        return r;
    });
}

void Session::finishRequest(quint64 op, const Result &result, const Writer &writer)
{
    const auto it = m_ops.find(op);
    if (it == m_ops.end())
        return;
    const Op entry = it.value();
    m_ops.erase(it);
    if (entry.completion) {
        entry.completion(result, writer);
        return;
    }
    if (result.ok())
        reply(entry.message, writer);
    else
        replyError(entry.message, result);
}

void Session::cancelAll()
{
    if (m_canceled)
        return;
    m_canceled = true;
    for (auto it = m_ops.begin(); it != m_ops.end(); ++it)
        it->token->cancel();
    m_ops.clear();
    m_publicOps.clear();
    for (auto it = m_handles.cbegin(); it != m_handles.cend(); ++it) {
        m_server->releaseHandle();
        Pool *pool = m_server->existingPool(it->loc);
        if (pool && pool->owns(it->worker)) {
            const quint32 handle = it->workerHandle;
            Pool::submitTo(it->worker, TaskContext(), [handle](Backend *, const Result &, Worker *worker) {
                if (worker)
                    worker->closeHandle(handle);
                return Result::success();
            });
        }
    }
    m_handles.clear();
    m_server->questions()->dropSession(m_id);
    if (m_discovering) {
        m_discovering = false;
        m_server->setDiscovering(m_id, false);
    }
    m_server->kickAll();
}

void Session::closeConnection()
{
    cancelAll();
    if (m_connection)
        m_connection->close();
}

// ------------------------------------------------------------- handlers

void Session::onHello(const Call &call, const SharedMessage &message)
{
    m_hello = true;
    qCDebug(lcNetVfsBridge).noquote() << m_server->tag() << "Hello from" << call.text << "protocol" << call.number;
    reply(message, [](WireWriter &w) {
        w.uint32(Protocol::Version).string(Protocol::bridgeVersion()).strings(Protocol::features());
    });
    if (m_server->consent() == Consent::Unknown)
        m_server->requestConsent();   // XB-6: first Hello while unknown
}

void Session::onGetConsent(const Call &, const SharedMessage &message)
{
    const QString consent = consentToString(m_server->consent());
    reply(message, [consent](WireWriter &w) { w.string(consent); });
}

void Session::onRequestConsent(const Call &, const SharedMessage &message)
{
    if (m_server->consent() != Consent::Granted)
        m_server->requestConsent();
    reply(message);
}

void Session::onListLocations(const Call &, const SharedMessage &message)
{
    // XB-6: nothing until granted.
    const QVector<LocationSpec> locations = m_server->consent() == Consent::Granted
        ? m_server->visibleLocations() : QVector<LocationSpec>();
    reply(message, [locations](WireWriter &w) {
        w.openArray("(sssa{sv})");
        for (const LocationSpec &spec : locations) {
            w.openStruct().string(spec.id).string(spec.provider).string(spec.name).variantMap(spec.info()).close();
        }
        w.close();
    });
}

void Session::onCapabilities(const Call &call, const SharedMessage &message)
{
    run(call, message, [](Backend *backend, Writer *out) {
        const Capabilities capabilities = backend->capabilities();
        *out = [capabilities](WireWriter &w) { Protocol::writeCapabilities(w, capabilities); };
        return Result::success();
    });
}

void Session::onDisconnect(const Call &call, const SharedMessage &message)
{
    Result error;
    if (!m_server->pool(call.loc, &error)) {
        replyError(message, error);
        return;
    }
    m_server->disconnectLocation(call.loc);
    reply(message);
}

void Session::onConnectAdHoc(Call &call, const SharedMessage &message)
{
    ConnectionParams params;
    QString path;
    Result r = Url::parse(call.text, &params, &path);   // XH-6: a password in the URL is refused
    if (r.ok() && params.provider == QLatin1String("local"))
        r = Result(Error::PermissionDenied, QStringLiteral("The bridge never accesses local files"));   // XB-11
    if (r.ok() && !BackendLoader::isAvailable(params.provider))
        r = Result(Error::Unsupported, QStringLiteral("No backend for %1 is installed").arg(params.provider));
    if (r.ok() && !call.adHoc.securityProfile.isEmpty() && params.provider != QLatin1String("smb"))
        r = Result(Error::ProtocolError, QStringLiteral("security_profile applies to SMB only"));
    if (!r.ok()) {
        wipeSecrets(&call);
        replyError(message, r, r.error() == Error::ProtocolError);
        return;
    }
    if (!call.adHoc.user.isEmpty())
        params.username = call.adHoc.user;
    if (!call.adHoc.securityProfile.isEmpty())
        params.options.insert(QStringLiteral("security_profile"), call.adHoc.securityProfile);

    LocationSpec spec;
    spec.kind = LocationKind::AdHoc;
    spec.provider = params.provider;
    spec.params = params;
    spec.startPath = path;
    spec.name = params.host;
    // XB-16: moved into Credentials (a deep copy) and wiped here.
    spec.adHocCredentials = std::make_shared<Credentials>(params.username, call.secret);
    wipeSecrets(&call);

    if (!needsInsecureConsent(params)) {
        connectAdHoc(spec, message);
        return;
    }
    QVariantMap details;
    details.insert(QStringLiteral("url"), Url::format(params, path));
    details.insert(QStringLiteral("provider"), params.provider);
    details.insert(QStringLiteral("host"), params.host);
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    m_server->questions()->ask(m_id, QLatin1String(QuestionKind::InsecureConsent), details,
                               [server, sessionId, spec, message](bool answered, QuestionAnswer answer) {
        Session *s = server->session(sessionId);
        if (!s)
            return;
        if (!answered || !answer.accept) {
            s->replyError(message, Result(Error::SecurityPolicy, QStringLiteral("The insecure connection was declined")));
            return;
        }
        LocationSpec accepted = spec;
        accepted.params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        s->connectAdHoc(accepted, message);
    });
}

void Session::connectAdHoc(const LocationSpec &specIn, const SharedMessage &message)
{
    LocationSpec spec = specIn;
    spec.id = m_server->reserveAdHocId();
    auto pool = std::make_shared<std::unique_ptr<Pool>>(
        std::make_unique<Pool>(spec, m_server->connector(), m_server->hosts()));
    Pool *raw = pool->get();
    BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    // Establishing is what the first item does (identity, then the secret).
    runOnPool(raw, Lane::Interactive, message, [](Backend *, Writer *) { return Result::success(); },
              [server, sessionId, spec, pool, message](const Result &result, const Writer &) {
        Session *s = server->session(sessionId);
        if (!result.ok()) {
            pool->reset();
            if (s)
                s->replyError(message, result);
            return;
        }
        const QString id = server->addAdHoc(spec, std::move(*pool));
        if (s)
            s->reply(message, [id](WireWriter &w) { w.string(id); });
    });
}

void Session::onForgetAdHoc(const Call &call, const SharedMessage &message)
{
    if (!m_server->forgetAdHoc(call.loc)) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such ad-hoc location")));
        return;
    }
    reply(message);
}

void Session::onDiscover(const Call &call, const SharedMessage &message)
{
    if (call.flag != m_discovering) {
        m_discovering = call.flag;
        m_server->setDiscovering(m_id, call.flag);
    }
    reply(message);
}

void Session::onCancel(const Call &call, const SharedMessage &message)
{
    const quint64 op = m_publicOps.value(call.number);
    if (op != 0) {
        const auto it = m_ops.constFind(op);
        if (it != m_ops.constEnd())
            it->token->cancel();
        m_server->kickAll();
    } else if (call.number == 0 || call.number >= m_nextPublicId) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such request or job")));
        return;
    }
    reply(message);   // an id that already finished: nothing to do
}

void Session::onAnswer(Call &call, const SharedMessage &message)
{
    QuestionAnswer answer;
    answer.accept = call.answer.accept;
    answer.answers.swap(call.answer.answers);   // single owner (XSEC-6)
    if (!m_server->questions()->answer(m_id, call.text, std::move(answer))) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such question")));
        return;
    }
    reply(message);
}

void Session::onOpenAccountSettings(const Call &call, const SharedMessage &message)
{
    LocationSpec spec;
    if (!m_server->findLocation(call.loc, &spec) || spec.kind != LocationKind::Account) {
        replyError(message, Result(Error::NotFound, QStringLiteral("No such account")));
        return;
    }
    const Result r = m_server->handoff().openAccountSettings(spec.accountId, spec.provider);
    if (r.ok())
        reply(message);
    else
        replyError(message, r);
}

void Session::onAddAccount(const Call &call, const SharedMessage &message)
{
    const Result r = m_server->handoff().addAccount(call.text);
    if (r.ok())
        reply(message);
    else
        replyError(message, r);
}

} // namespace Bridge
} // namespace NetVfs
