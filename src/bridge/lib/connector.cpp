// SPDX-License-Identifier: LGPL-2.1-or-later
#include "connector.h"

#include "bridgelog.h"
#include "bridgeserver.h"
#include "identity.h"
#include "secure.h"
#include "serverparts.h"

#include <QtCore/QCryptographicHash>

namespace NetVfs::Bridge {

namespace {

constexpr int FetchTimeoutMs = 60000;

struct Fetch {
    Result result;
    ConnectionParams params;
    Credentials credentials;
};

struct Asked {
    bool answered = false;
    QuestionAnswer answer;
};

struct AskState {
    Rendezvous<Asked> rendezvous;
    std::mutex mutex;
    QString id;                       // set on the main thread
};

} // namespace

BridgeConnector::BridgeConnector(BridgeServer *server, KnownHosts *knownHosts, int questionTimeoutMs)
    : m_server(server)
    , m_knownHosts(knownHosts)
    , m_questionTimeoutMs(questionTimeoutMs)
{
}

QVariantMap BridgeConnector::identityDetails(const ServerIdentity &identity, const LocationSpec &spec)
{
    QVariantMap details;
    details.insert(QStringLiteral("location"), spec.id);
    details.insert(QStringLiteral("host"), spec.params.host);
    details.insert(QStringLiteral("port"), spec.params.port);
    details.insert(QStringLiteral("provider"), spec.provider);
    details.insert(QStringLiteral("kind"), identity.kind == ServerIdentity::Kind::TlsCertificate
                                               ? QStringLiteral("tls") : QStringLiteral("ssh"));
    details.insert(QStringLiteral("algorithm"), identity.algorithm);
    QString fingerprint = identity.fingerprint;
    if (fingerprint.isEmpty() && !identity.publicKey.isEmpty()) {
        // OpenSSH form: "SHA256:" + unpadded base64 of the key blob's digest.
        fingerprint = QStringLiteral("SHA256:") + QString::fromLatin1(
            QCryptographicHash::hash(identity.publicKey, QCryptographicHash::Sha256)
                .toBase64(QByteArray::OmitTrailingEquals));
    }
    details.insert(QStringLiteral("fingerprint"), fingerprint);
    details.insert(QStringLiteral("publicKey"), identity.publicKey);
    details.insert(QStringLiteral("systemTrusted"), identity.systemTrusted);
    details.insert(QStringLiteral("problems"), identity.problems);
    for (auto it = identity.details.constBegin(); it != identity.details.constEnd(); ++it) {
        const QVariant &v = it.value();
        // Only values the wire can carry; dates as ISO strings.
        if (v.type() == QVariant::DateTime)
            details.insert(it.key(), v.toDateTime().toUTC().toString(Qt::ISODate));
        else if (!variantSignature(v).isEmpty())
            details.insert(it.key(), v);
    }
    return details;
}

bool BridgeConnector::ask(const TaskContext &context, const QString &kind, const QVariantMap &details,
                          QuestionAnswer *answer)
{
    auto state = std::make_shared<AskState>();
    BridgeServer *server = m_server;
    const quint64 sessionId = context.sessionId;
    server->mainQueue()->post([server, state, sessionId, kind, details]() {
        const QString id = server->questions()->ask(sessionId, kind, details,
                                                    [state](bool answered, QuestionAnswer a) {
                                                        state->rendezvous.set(Asked { answered, std::move(a) });
                                                    });
        std::scoped_lock lock(state->mutex);
        state->id = id;
    });
    Asked asked;
    if (!state->rendezvous.wait(context.token.get(), m_questionTimeoutMs, &asked)) {
        server->mainQueue()->post([server, state]() {
            std::scoped_lock lock(state->mutex);
            if (!state->id.isEmpty())
                server->questions()->cancel(state->id);
        });
        return false;
    }
    *answer = std::move(asked.answer);
    return asked.answered && answer->accept;
}

Result BridgeConnector::establish(Backend *backend, const LocationSpec &spec, const TaskContext &context)
{
    if (spec.kind == LocationKind::Account)
        return establishAccount(backend, spec, context);
    return establishAdHoc(backend, spec, context);
}

Result BridgeConnector::establishAccount(Backend *backend, const LocationSpec &spec, const TaskContext &context)
{
    auto fetched = std::make_shared<Rendezvous<std::shared_ptr<Fetch>>>();
    const BridgeServer *server = m_server;
    const int accountId = spec.accountId;
    server->mainQueue()->post([server, fetched, accountId]() {
        server->locations()->fetch(accountId, [fetched](const Result &r, const ConnectionParams &p, const Credentials &c) {
            auto f = std::make_shared<Fetch>();
            f->result = r;
            f->params = p;
            f->credentials = c;
            fetched->set(f);
        });
    });
    std::shared_ptr<Fetch> f;
    if (!fetched->wait(context.token.get(), FetchTimeoutMs, &f))
        return Result(context.canceled() ? Error::Canceled : Error::Timeout, QStringLiteral("No account data"));
    if (!f->result.ok())
        return f->result;
    QuestionPrompter prompter(this, context);
    ServerIdentity seen;
    const Result r = NetVfs::establish(backend, f->params, f->credentials, &seen, &prompter);
    f->credentials.wipe();
    if (const Attention attention = attentionForError(r.error()); attention != Attention::None) {
        // XB-14: as Buteo does (SPEC 6.4); the pin seen is recorded for review.
        const QString pin = attention == Attention::ServerIdentityChanged || r.error() == Error::ServerIdentityUnknown
            ? seen.toPin() : QString();
        server->mainQueue()->post([server, accountId, attention, pin]() {
            server->locations()->setAttention(accountId, attention, pin);
        });
    }
    return r;
}

Result BridgeConnector::checkAdHocIdentity(const ServerIdentity &seen, const LocationSpec &spec,
                                           const TaskContext &context)
{
    const QString key = spec.hostKey();
    if (const Result r = checkServerIdentity(seen, m_knownHosts->pin(key)); r.error() != Error::ServerIdentityUnknown)
        return r;
    if (QuestionAnswer answer;
        !ask(context, QLatin1String(QuestionKind::IdentityUnknown), identityDetails(seen, spec), &answer)) {
        if (context.canceled())
            return Result(Error::Canceled);
        return Result(Error::ServerIdentityUnknown, QStringLiteral("The server identity was not accepted"));
    }
    if (!m_knownHosts->setPin(key, seen.toPin()))
        qCWarning(lcNetVfsBridge).noquote() << m_server->tag() << "Cannot store an accepted server identity";
    return Result::success();
}

Result BridgeConnector::establishAdHoc(Backend *backend, const LocationSpec &spec, const TaskContext &context)
{
    ServerIdentity seen;
    Result r = backend->connect(spec.params, &seen);
    if (!r.ok())
        return r;
    r = checkAdHocIdentity(seen, spec, context);
    if (!r.ok()) {
        backend->disconnect();   // C-7: nothing else is sent
        return r;
    }
    QuestionPrompter prompter(this, context);
    const Credentials credentials = spec.adHocCredentials ? *spec.adHocCredentials : Credentials();
    r = backend->authenticate(credentials, &prompter);
    if (!r.ok())
        backend->disconnect();
    return r;
}

QuestionPrompter::QuestionPrompter(BridgeConnector *connector, const TaskContext &context)
    : m_connector(connector)
    , m_context(context)
{
}

bool QuestionPrompter::answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                              QVector<QByteArray> *answers)
{
    QStringList texts;
    QVariantList echo;
    for (const AuthPrompt &prompt : prompts) {
        texts << prompt.text;
        echo << prompt.echo;
    }
    QVariantMap details;
    details.insert(QStringLiteral("name"), name);
    details.insert(QStringLiteral("instruction"), instruction);
    details.insert(QStringLiteral("prompts"), texts);
    details.insert(QStringLiteral("echo"), echo);
    QuestionAnswer reply;
    if (!m_connector->ask(m_context, QLatin1String(QuestionKind::KeyboardInteractive), details, &reply))
        return false;
    if (reply.answers.size() != prompts.size()) {
        for (QByteArray &a : reply.answers)
            secureWipe(a);
        return false;
    }
    answers->swap(reply.answers);   // single owner; the backend wipes them after use (XSEC-6)
    return true;
}

} // namespace NetVfs::Bridge
