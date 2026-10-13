// SPDX-License-Identifier: LGPL-2.1-or-later
// conn_establish (design §1.2): the two pieces of security ordering that stay
// in C++, inside one call so that no caller can authenticate before the
// identity check has passed:
//  - C-7, XSEC-1: connect, then the identity verdict, then the credentials,
//    then authenticate; any failure after connect disconnects, so nothing
//    else is sent.
//  - XA-6: an account's secret comes from signond, fetched on the Qt thread
//    only after the identity was accepted (design §6.8), and wiped after
//    authenticate (SEC-5).
// Keyboard-interactive prompts (XC-15) go to the caller's prompt hook.
#include "ffi_p.h"

#include "identity.h"
#include "secretsource.h"
#include "secure.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QPointer>

#include <algorithm>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <mutex>
#include <stdexcept>

void nvb_reply::wipe()
{
    for (QByteArray &answer : answers)
        NetVfs::secureWipe(answer);
    answers.clear();
}

namespace NetVfs::Ffi {

namespace {

constexpr int SecretTimeoutMs = 60000;   // as the C++ bridge waited for account data
constexpr int WaitSliceMs = 50;          // C-9: a cancel ends the wait within this

// ------------------------------------------------------------- identity

uint32_t identityKind(ServerIdentity::Kind kind)
{
    switch (kind) {
    case ServerIdentity::Kind::SshHostKey:
        return NVB_IDENTITY_SSH;
    case ServerIdentity::Kind::TlsCertificate:
        return NVB_IDENTITY_TLS;
    default:
        return NVB_IDENTITY_NONE;
    }
}

// XC-16 as connector.cpp showed it: OpenSSH form "SHA256:" + unpadded base64
// of the key blob's digest when the backend left the fingerprint empty.
QString fingerprintOf(const ServerIdentity &identity)
{
    if (!identity.fingerprint.isEmpty() || identity.publicKey.isEmpty())
        return identity.fingerprint;
    return QStringLiteral("SHA256:") + QString::fromLatin1(
        QCryptographicHash::hash(identity.publicKey, QCryptographicHash::Sha256)
            .toBase64(QByteArray::OmitTrailingEquals));
}

void fillIdentity(HoldArena &arena, nvb_identity *out, const ServerIdentity &seen)
{
    out->kind = identityKind(seen.kind);
    out->algorithm = arena.bytes(seen.algorithm.toUtf8());
    out->public_key = arena.bytes(seen.publicKey);
    out->fingerprint = arena.bytes(fingerprintOf(seen).toUtf8());
    out->pin = arena.bytes(seen.toPin().toUtf8());
    out->system_trusted = seen.systemTrusted ? 1 : 0;
    out->problems = seen.problems;
    out->details = fillMap(arena, seen.details, &out->n_details);
}

// The identity check and the hook's verdict on it.
Result identityVerdict(const nvb_conn *conn, const ServerIdentity &seen, const QString &pin,
                       const nvb_establish_hooks *hooks)
{
    const Result check = checkServerIdentity(seen, pin);
    uint32_t verdict = NVB_ID_USE_CHECK;
    if (hooks && hooks->identity) {
        HoldArena arena;
        nvb_identity identity {};
        fillIdentity(arena, &identity, seen);
        nvb_error error {};
        fillError(arena, &error, check);
        verdict = hooks->identity(hooks->ctx, &identity, check.ok() ? nullptr : &error);
    }
    if (verdict == NVB_ID_CANCEL || conn->canceled.load())
        return Result(Error::Canceled);
    // Only an unknown identity may be accepted, never a changed one.
    if (verdict == NVB_ID_ACCEPT_UNKNOWN && check.error() == Error::ServerIdentityUnknown)
        return Result::success();
    return check;
}

// ------------------------------------------------------------- prompts

// AuthPrompter over the prompt hook (the C++ bridge's QuestionPrompter).
class HookPrompter final : public AuthPrompter
{
public:
    HookPrompter(const nvb_conn *conn, const nvb_establish_hooks *hooks) : m_conn(conn), m_hooks(hooks) {}

    bool answer(const QString &name, const QString &instruction, const QVector<AuthPrompt> &prompts,
                QVector<QByteArray> *answers) override
    {
        HoldArena arena;
        std::vector<nvb_prompt> items(static_cast<size_t>(prompts.size()));
        for (int i = 0; i < prompts.size(); ++i) {
            items[static_cast<size_t>(i)].text = arena.bytes(prompts.at(i).text.toUtf8());
            items[static_cast<size_t>(i)].echo = prompts.at(i).echo ? 1 : 0;
        }
        nvb_reply reply;   // wiped when it goes
        const int given = m_hooks->prompt(m_hooks->ctx, arena.bytes(name.toUtf8()),
                                          arena.bytes(instruction.toUtf8()), items.data(), items.size(), &reply);
        // A count that differs from the prompts declines (design §1.2).
        if (!given || m_canceled.load() || m_conn->canceled.load() || reply.answers.size() != prompts.size())
            return false;
        answers->swap(reply.answers);   // single owner; the backend wipes them after use (XSEC-6)
        return true;
    }

    // XC-22: the hook watches the caller's own cancel flag; answers that
    // arrive after a cancel are dropped.
    void cancel() override { m_canceled.store(true); }

private:
    const nvb_conn *m_conn;
    const nvb_establish_hooks *m_hooks;
    std::atomic<bool> m_canceled { false };
};

// -------------------------------------------------------------- secrets

// One signond lookup, handed from the Qt thread to the waiting owner thread.
struct SecretWait {
    std::mutex mutex;
    std::condition_variable cond;
    bool done = false;
    bool abandoned = false;            // the owner gave up: wipe what still arrives
    Result result;
    Credentials credentials;
    QPointer<SecretSource> source;     // Qt thread only

    void finish(const Result &r, const Credentials &c)
    {
        std::scoped_lock lock(mutex);
        if (done || abandoned)
            return;
        result = r;
        credentials = c;
        done = true;
        cond.notify_all();
    }
};

// Qt thread: starts the lookup (as helperdirectory.cpp's fetchSecret did).
void startLookup(const std::shared_ptr<SecretWait> &wait, quint32 credentialsId, bool secretOptional)
{
    {
        std::scoped_lock lock(wait->mutex);
        if (wait->abandoned)
            return;   // canceled or timed out while queued: signond is not asked
    }
    // Deleted through deleteLater() when it answers, else with the application.
    auto *source = new SignonSecretSource(QCoreApplication::instance());
    source->setSecretOptional(secretOptional);
    wait->source = source;
    QObject::connect(source, &SecretSource::fetched, source, [wait, source](const Credentials &fetched) {
        wait->finish(Result::success(), fetched);
        source->deleteLater();
    });
    QObject::connect(source, &SecretSource::failed, source, [wait, source](const Result &failure) {
        wait->finish(failure, Credentials());
        source->deleteLater();
    });
    source->fetch(credentialsId);
}

// Owner thread: waits for the lookup, at most 60 s, ending early on cancel.
Result awaitLookup(const nvb_conn *conn, const std::shared_ptr<SecretWait> &wait, Credentials *out)
{
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(SecretTimeoutMs);
    std::unique_lock lock(wait->mutex);
    while (!wait->done && !conn->canceled.load() && Clock::now() < deadline)
        wait->cond.wait_for(lock, std::chrono::milliseconds(WaitSliceMs));
    if (wait->done) {
        *out = wait->credentials;
        wait->credentials.wipe();
        return wait->result;
    }
    wait->abandoned = true;
    lock.unlock();
    postToQt([wait]() {
        if (wait->source)
            wait->source->deleteLater();   // ends the session with signond
    });
    if (conn->canceled.load())
        return Result(Error::Canceled);
    return Result(Error::Timeout, QStringLiteral("The account secret did not arrive in time"));
}

// XA-6, A-6, XA-7: an account's secret from signond.
Result signonCredentials(const nvb_conn *conn, const nvb_secret &secret, Credentials *out)
{
    if (onQtThread())
        return Result(Error::Internal, QStringLiteral("A signond lookup cannot wait on the Qt thread"));
    auto wait = std::make_shared<SecretWait>();
    const quint32 id = secret.credentials_id;
    const bool optional = secret.secret_optional != 0;
    if (!postToQt([wait, id, optional]() { startLookup(wait, id, optional); }))
        return Result(Error::Internal, QStringLiteral("The Qt event loop is not running"));
    const Result r = awaitLookup(conn, wait, out);
    if (r.ok() && out->userName.isEmpty())
        out->userName = toUtf8String(secret.user);
    return r;
}

Result credentialsFor(const nvb_conn *conn, const nvb_secret *secret, Credentials *out)
{
    if (!secret)
        return Result::success();
    switch (secret->source) {
    case NVB_SECRET_NONE:
        *out = Credentials(toUtf8String(secret->user), QByteArray());
        return Result::success();
    case NVB_SECRET_BYTES:
        // fromRawData: Credentials makes the only copy (O5).
        *out = Credentials(toUtf8String(secret->user),
                           QByteArray::fromRawData(reinterpret_cast<const char *>(secret->secret.ptr),
                                                   static_cast<int>(std::min<size_t>(secret->secret.len, INT_MAX))));
        return Result::success();
    case NVB_SECRET_SIGNON:
        return signonCredentials(conn, *secret, out);
    default:
        return Result(Error::Internal, QStringLiteral("Unknown secret source"));
    }
}

// Disconnects on any failure after connect, also a thrown one (C-7).
class DisconnectOnFailure
{
public:
    explicit DisconnectOnFailure(Backend *backend) : m_backend(backend) {}
    DisconnectOnFailure(const DisconnectOnFailure &) = delete;
    DisconnectOnFailure &operator=(const DisconnectOnFailure &) = delete;
    ~DisconnectOnFailure()
    {
        if (m_backend)
            m_backend->disconnect();
    }
    void succeeded() { m_backend = nullptr; }

private:
    Backend *m_backend;
};

// Identity verdict, credentials, authenticate.
Result afterConnect(nvb_conn *conn, const ServerIdentity &seen, const QString &pin, const nvb_secret *secret,
                    const nvb_establish_hooks *hooks, uint32_t *phase)
{
    *phase = NVB_PHASE_IDENTITY;
    if (const Result r = identityVerdict(conn, seen, pin, hooks); !r.ok())
        return r;
    *phase = NVB_PHASE_CREDENTIALS;
    Credentials credentials;
    if (const Result r = credentialsFor(conn, secret, &credentials); !r.ok())
        return r;
    *phase = NVB_PHASE_AUTHENTICATE;
    HookPrompter prompter(conn, hooks);
    const bool prompts = hooks && hooks->prompt;
    const Result r = conn->backend->authenticate(credentials, prompts ? &prompter : nullptr);
    credentials.wipe();   // SEC-5
    return r;
}

// The sequence; *phase says how far it got.
Result establish(nvb_conn *conn, const ConnectionParams &params, const QString &pin, const nvb_secret *secret,
                 const nvb_establish_hooks *hooks, uint32_t *phase)
{
    Backend *backend = backendOf(conn);
    *phase = NVB_PHASE_CONNECT;
    ServerIdentity seen;
    if (const Result r = backend->connect(params, &seen); !r.ok())
        return r;   // as identity.cpp: nothing to disconnect
    DisconnectOnFailure guard(backend);   // nothing else is sent after a failure
    const Result r = afterConnect(conn, seen, pin, secret, hooks, phase);
    if (r.ok()) {
        guard.succeeded();
        *phase = NVB_PHASE_DONE;
    }
    return r;
}

} // namespace

nvb_error *connEstablish(nvb_conn *conn, const nvb_params *params, nvb_bytes pin, const nvb_secret *secret,
                         const nvb_establish_hooks *hooks, uint32_t *phase) noexcept
{
    uint32_t reached = NVB_PHASE_CONNECT;
    nvb_error *error = guarded([conn, params, pin, secret, hooks, &reached]() {
        if (!params)
            throw std::invalid_argument("no parameters");
        ConnectionParams p;
        if (const Result r = toParams(*params, &p); !r.ok())
            return r;
        return establish(conn, p, toUtf8String(pin), secret, hooks, &reached);
    });
    if (phase)
        *phase = reached;
    return error;
}

void replySet(nvb_reply *reply, const nvb_bytes *answers, size_t count) noexcept
{
    guardedVoid([reply, answers, count]() {
        if (!reply)
            return;
        reply->wipe();
        if (!answers)
            return;
        reply->answers.reserve(static_cast<int>(std::min<size_t>(count, INT_MAX)));
        for (size_t i = 0; i < count; ++i)
            reply->answers.append(toByteArray(answers[i]));
    });
}

} // namespace NetVfs::Ffi
