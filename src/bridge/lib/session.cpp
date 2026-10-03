// SPDX-License-Identifier: LGPL-2.1-or-later
#include "session.h"

#include "backendloader.h"
#include "bridgelog.h"
#include "bridgeserver.h"
#include "protocol.h"
#include "secure.h"
#include "serverparts.h"
#include "url.h"

#include <dbus/dbus.h>

namespace NetVfs::Bridge {

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

// The URL, the user and the profile of an ad-hoc location; XH-6: a password in
// the URL is refused.
Result parseAdHoc(const Call &call, ConnectionParams *params, QString *path)
{
    Result r = Url::parse(call.text, params, path);
    if (r.ok() && params->provider == QLatin1String("local"))
        r = Result(Error::PermissionDenied, QStringLiteral("The bridge never accesses local files"));   // XB-11
    if (r.ok() && !BackendLoader::isAvailable(params->provider))
        r = Result(Error::Unsupported, QStringLiteral("No backend for %1 is installed").arg(params->provider));
    if (r.ok() && !call.adHoc.securityProfile.isEmpty() && params->provider != QLatin1String("smb"))
        r = Result(Error::ProtocolError, QStringLiteral("security_profile applies to SMB only"));
    return r;
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
    if (const MethodInfo *info = findMethod(member);
        info && info->needsConsent && m_server->consent() != Consent::Granted) {
        wipeSecrets(&call);
        replyError(message, Result(Error::PermissionDenied,
                                   QStringLiteral("The user has not allowed this app to use network locations")));
        return;
    }
    dispatch(call, message);
    wipeSecrets(&call);
}

void Session::dispatch(Call &call, const SharedMessage &message)
{
    if (dispatchAdmin(call, message) || dispatchFiles(call, message) || dispatchJobs(call, message))
        return;
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
    if (m_server->quota()->acquireRequest())
        return true;
    replyError(message, Result(Error::TooManyConnections, QStringLiteral("Too many requests"), QString(),
                               ConsumerLimits::RetryAfterMs));
    return false;
}

Pool *Session::poolFor(const QString &loc, const SharedMessage &message)
{
    Result error;
    Pool *pool = m_server->locations()->pool(loc, &error);
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
    const BridgeServer *server = m_server;
    const quint64 sessionId = m_id;
    pool->submit(lane, context(op), [server, sessionId, op, work](Backend *backend, const Result &ready, Worker *) {
        Writer writer;
        const Result r = ready.ok() ? work(backend, &writer) : ready;
        server->mainQueue()->post([server, sessionId, op, r, writer]() {
            server->quota()->releaseRequest();
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
        m_server->quota()->releaseHandle();
        m_server->locations()->closeWorkerHandle(it->loc, it->worker, it->workerHandle);
    }
    m_handles.clear();
    m_server->questions()->dropSession(m_id);
    if (m_discovering) {
        m_discovering = false;
        m_server->nearby()->setDiscovering(m_id, false);
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

// The session, the locations, the questions and the handoff.
class Session::Admin
{
public:
    explicit Admin(Session &session) : m_session(session) {}

    // Handles the calls of this area; false for any other method.
    bool dispatch(Call &call, const SharedMessage &message) const;
    // An accepted ad-hoc location: its pool connects first (XB-14).
    void connectAdHoc(const LocationSpec &specIn, const SharedMessage &message) const;

private:
    using Handler = void (Admin::*)(const Call &call, const SharedMessage &message) const;

    void onHello(const Call &call, const SharedMessage &message) const;
    void onGetConsent(const Call &call, const SharedMessage &message) const;
    void onRequestConsent(const Call &call, const SharedMessage &message) const;
    void onListLocations(const Call &call, const SharedMessage &message) const;
    void onCapabilities(const Call &call, const SharedMessage &message) const;
    void onDisconnect(const Call &call, const SharedMessage &message) const;
    void onConnectAdHoc(Call &call, const SharedMessage &message) const;   // moves the secret out
    void onForgetAdHoc(const Call &call, const SharedMessage &message) const;
    void onDiscover(const Call &call, const SharedMessage &message) const;
    void onCancel(const Call &call, const SharedMessage &message) const;
    void onAnswer(Call &call, const SharedMessage &message) const;         // moves the answers out
    void onOpenAccountSettings(const Call &call, const SharedMessage &message) const;
    void onAddAccount(const Call &call, const SharedMessage &message) const;

    Session &m_session;
};

bool Session::dispatchAdmin(Call &call, const SharedMessage &message)
{
    return Admin(*this).dispatch(call, message);
}

bool Session::Admin::dispatch(Call &call, const SharedMessage &message) const
{
    if (call.method == Method::ConnectAdHoc) {
        onConnectAdHoc(call, message);
        return true;
    }
    if (call.method == Method::Answer) {
        onAnswer(call, message);
        return true;
    }
    static const QHash<int, Handler> handlers = {
        { static_cast<int>(Method::Hello), &Admin::onHello },
        { static_cast<int>(Method::GetConsent), &Admin::onGetConsent },
        { static_cast<int>(Method::RequestConsent), &Admin::onRequestConsent },
        { static_cast<int>(Method::ListLocations), &Admin::onListLocations },
        { static_cast<int>(Method::Capabilities), &Admin::onCapabilities },
        { static_cast<int>(Method::Disconnect), &Admin::onDisconnect },
        { static_cast<int>(Method::ForgetAdHoc), &Admin::onForgetAdHoc },
        { static_cast<int>(Method::Discover), &Admin::onDiscover },
        { static_cast<int>(Method::Cancel), &Admin::onCancel },
        { static_cast<int>(Method::OpenAccountSettings), &Admin::onOpenAccountSettings },
        { static_cast<int>(Method::AddAccount), &Admin::onAddAccount },
    };
    const auto it = handlers.constFind(static_cast<int>(call.method));
    if (it == handlers.constEnd())
        return false;
    (this->*(it.value()))(call, message);
    return true;
}

void Session::Admin::onHello(const Call &call, const SharedMessage &message) const
{
    BridgeServer *server = m_session.m_server;
    m_session.m_hello = true;
    qCDebug(lcNetVfsBridge).noquote() << server->tag() << "Hello from" << call.text << "protocol" << call.number;
    m_session.reply(message, [](WireWriter &w) {
        w.uint32(Protocol::Version).string(Protocol::bridgeVersion()).strings(Protocol::features());
    });
    if (server->consent() == Consent::Unknown)
        server->requestConsent();   // XB-6: first Hello while unknown
}

void Session::Admin::onGetConsent(const Call &, const SharedMessage &message) const
{
    const QString consent = consentToString(m_session.m_server->consent());
    m_session.reply(message, [consent](WireWriter &w) { w.string(consent); });
}

void Session::Admin::onRequestConsent(const Call &, const SharedMessage &message) const
{
    if (m_session.m_server->consent() != Consent::Granted)
        m_session.m_server->requestConsent();
    m_session.reply(message);
}

void Session::Admin::onListLocations(const Call &, const SharedMessage &message) const
{
    // XB-6: nothing until granted.
    const QVector<LocationSpec> locations = m_session.m_server->consent() == Consent::Granted
        ? m_session.m_server->locations()->visible() : QVector<LocationSpec>();
    m_session.reply(message, [locations](WireWriter &w) {
        w.openArray("(sssa{sv})");
        for (const LocationSpec &spec : locations) {
            w.openStruct().string(spec.id).string(spec.provider).string(spec.name).variantMap(spec.info()).close();
        }
        w.close();
    });
}

void Session::Admin::onCapabilities(const Call &call, const SharedMessage &message) const
{
    m_session.run(call, message, [](const Backend *backend, Writer *out) {
        const Capabilities capabilities = backend->capabilities();
        *out = [capabilities](WireWriter &w) { Protocol::writeCapabilities(w, capabilities); };
        return Result::success();
    });
}

void Session::Admin::onDisconnect(const Call &call, const SharedMessage &message) const
{
    LocationBook *locations = m_session.m_server->locations();
    if (Result error; !locations->pool(call.loc, &error)) {
        m_session.replyError(message, error);
        return;
    }
    locations->disconnect(call.loc);
    m_session.reply(message);
}

void Session::Admin::onConnectAdHoc(Call &call, const SharedMessage &message) const
{
    ConnectionParams params;
    QString path;
    if (const Result r = parseAdHoc(call, &params, &path); !r.ok()) {
        wipeSecrets(&call);
        m_session.replyError(message, r, r.error() == Error::ProtocolError);
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
    const BridgeServer *server = m_session.m_server;
    const quint64 sessionId = m_session.m_id;
    m_session.m_server->questions()->ask(sessionId, QLatin1String(QuestionKind::InsecureConsent), details,
                                         [server, sessionId, spec, message](bool answered, const QuestionAnswer &answer) {
        Session *s = server->session(sessionId);
        if (!s)
            return;
        if (!answered || !answer.accept) {
            s->replyError(message, Result(Error::SecurityPolicy,
                                          QStringLiteral("The insecure connection was declined")));
            return;
        }
        LocationSpec accepted = spec;
        accepted.params.options.insert(QStringLiteral("allow_insecure"), QStringLiteral("true"));
        Admin(*s).connectAdHoc(accepted, message);
    });
}

void Session::Admin::connectAdHoc(const LocationSpec &specIn, const SharedMessage &message) const
{
    const BridgeServer *server = m_session.m_server;
    LocationBook *locations = server->locations();
    LocationSpec spec = specIn;
    spec.id = locations->reserveAdHocId();
    auto pool = std::make_shared<std::unique_ptr<Pool>>(
        std::make_unique<Pool>(spec, locations->connector(), locations->hosts()));
    Pool *raw = pool->get();
    const quint64 sessionId = m_session.m_id;
    // Establishing is what the first item does (identity, then the secret).
    m_session.runOnPool(raw, Lane::Interactive, message, [](Backend *, Writer *) { return Result::success(); },
                        [server, sessionId, spec, pool, message](const Result &result, const auto &) {
        Session *s = server->session(sessionId);
        if (!result.ok()) {
            pool->reset();
            if (s)
                s->replyError(message, result);
            return;
        }
        const QString id = server->locations()->addAdHoc(spec, std::move(*pool));
        if (s)
            s->reply(message, [id](WireWriter &w) { w.string(id); });
    });
}

void Session::Admin::onForgetAdHoc(const Call &call, const SharedMessage &message) const
{
    if (!m_session.m_server->locations()->forgetAdHoc(call.loc)) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such ad-hoc location")));
        return;
    }
    m_session.reply(message);
}

void Session::Admin::onDiscover(const Call &call, const SharedMessage &message) const
{
    if (call.flag != m_session.m_discovering) {
        m_session.m_discovering = call.flag;
        m_session.m_server->nearby()->setDiscovering(m_session.m_id, call.flag);
    }
    m_session.reply(message);
}

void Session::Admin::onCancel(const Call &call, const SharedMessage &message) const
{
    if (const quint64 op = m_session.m_publicOps.value(call.number); op != 0) {
        if (const auto it = m_session.m_ops.constFind(op); it != m_session.m_ops.constEnd())
            it->token->cancel();
        m_session.m_server->kickAll();
    } else if (call.number == 0 || call.number >= m_session.m_nextPublicId) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such request or job")));
        return;
    }
    m_session.reply(message);   // an id that already finished: nothing to do
}

void Session::Admin::onAnswer(Call &call, const SharedMessage &message) const
{
    QuestionAnswer answer;
    answer.accept = call.answer.accept;
    answer.answers.swap(call.answer.answers);   // single owner (XSEC-6)
    if (!m_session.m_server->questions()->answer(m_session.m_id, call.text, std::move(answer))) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such question")));
        return;
    }
    m_session.reply(message);
}

void Session::Admin::onOpenAccountSettings(const Call &call, const SharedMessage &message) const
{
    LocationSpec spec;
    if (!m_session.m_server->locations()->find(call.loc, &spec) || spec.kind != LocationKind::Account) {
        m_session.replyError(message, Result(Error::NotFound, QStringLiteral("No such account")));
        return;
    }
    const Result r = m_session.m_server->handoff().openAccountSettings(spec.accountId, spec.provider);
    if (r.ok())
        m_session.reply(message);
    else
        m_session.replyError(message, r);
}

void Session::Admin::onAddAccount(const Call &call, const SharedMessage &message) const
{
    const Result r = m_session.m_server->handoff().addAccount(call.text);
    if (r.ok())
        m_session.reply(message);
    else
        m_session.replyError(message, r);
}

} // namespace NetVfs::Bridge
