// SPDX-License-Identifier: LGPL-2.1-or-later
#include "netvfsprobe.h"
#include "accountsession.h"
#include "backendloader.h"
#include "errortexts.h"
#include "identity.h"
#include "logging.h"
#include "netvfshelpers.h"
#include "probe.h"
#include "secure.h"

#include <memory>

using namespace NetVfs;

namespace NetVfsUi {

static_assert(static_cast<int>(Error::Internal) == static_cast<int>(NetVfsProbe::Internal),
              "NetVfsProbe::ErrorCode must mirror NetVfs::Error");
static_assert(static_cast<int>(Error::AuthFailed) == static_cast<int>(NetVfsProbe::AuthFailed),
              "NetVfsProbe::ErrorCode must mirror NetVfs::Error");

namespace {
constexpr const char *HostKeyOption = "host_key";

NetVfsProbe::IdentityStatus identityStatusFor(const ProbeOutcome &outcome)
{
    switch (outcome.identityCheck.error()) {
    case Error::None:
        return outcome.identity.isEmpty() ? NetVfsProbe::NoIdentity : NetVfsProbe::IdentityMatches;
    case Error::ServerIdentityUnknown:
        return NetVfsProbe::IdentityUnknown;
    default:
        return NetVfsProbe::IdentityChanged;
    }
}

Credentials credentialsFromVariant(const QVariantMap &map, const QString &fallbackUser)
{
    QString user = map.value(QStringLiteral("username")).toString().trimmed();
    if (user.isEmpty())
        user = fallbackUser;
    QString secret = map.value(QStringLiteral("secret")).toString();
    QByteArray bytes = secret.toUtf8();
    secureWipe(secret);
    const Credentials credentials(user, bytes);
    secureWipe(bytes);
    return credentials;
}

AccountSession *openSession(int accountId, QObject *parent)
{
    return AccountSession::open(accountId, parent);
}
} // namespace

ProbeOutcome runIdentify(Backend *backend, const ConnectionParams &params)
{
    ProbeOutcome outcome;
    outcome.result = backend->connect(params, &outcome.identity);
    if (outcome.result.ok()) {
        outcome.identityCheck = checkServerIdentity(outcome.identity, params.option(QLatin1String(HostKeyOption)));
        backend->disconnect();
    }
    return outcome;
}

ProbeOutcome runVerify(Backend *backend, const ConnectionParams &params, const Credentials &credentials,
                       const QString &backupsPath)
{
    ProbeOutcome outcome;
    outcome.result = establish(backend, params, credentials, &outcome.identity);
    outcome.identityCheck = checkServerIdentity(outcome.identity, params.option(QLatin1String(HostKeyOption)));
    if (outcome.result.ok()) {
        outcome.result = verifyAccess(backend, backupsPath, &outcome.freeBytes);
        backend->disconnect();
    }
    return outcome;
}

NetVfsProbe::NetVfsProbe(QObject *parent)
    : QObject(parent)
    , m_sessionFactory(openSession)
{
}

NetVfsProbe::~NetVfsProbe()
{
    closeSession();
}

QVariantMap NetVfsProbe::serverIdentity() const
{
    return identityToVariant(m_identity);
}

void NetVfsProbe::identify(const QVariantMap &paramsMap)
{
    reset();
    const ConnectionParams params = paramsFromVariant(paramsMap);
    Backend *backend = createBackend(params.provider);
    if (!backend)
        return;
    qCDebug(lcNetVfsUi) << "Identifying" << params.host;
    setState(Identifying);
    auto outcome = std::make_shared<ProbeOutcome>();
    m_jobs.start([backend, params, outcome](CancelToken *token) {
        std::unique_ptr<Backend> owned(backend);
        token->attach(backend);
        *outcome = runIdentify(backend, params);
        token->detach();
    }, [this, outcome]() { finishIdentify(*outcome); });
}

void NetVfsProbe::verify(const QVariantMap &paramsMap, const QVariantMap &credentialsMap,
                         const QString &backupsPath)
{
    reset();
    const ConnectionParams params = paramsFromVariant(paramsMap);
    const Credentials credentials = credentialsFromVariant(credentialsMap, params.username);
    startVerify(params, credentials, backupsPath);
}

void NetVfsProbe::verifyAccount(int accountId, const QString &pin)
{
    reset();
    setState(Verifying);
    AccountSession *session = m_sessionFactory(accountId, this);
    m_session = session;
    connect(session, &AccountSession::ready, this, [this, session, pin]() {
        ConnectionParams params = session->params();
        if (!pin.isEmpty())
            params.options.insert(QLatin1String(HostKeyOption), pin);
        const Credentials credentials = session->credentials();
        const QString backupsPath = session->backupsPath();
        closeSession();
        startVerify(params, credentials, backupsPath);
    });
    connect(session, &AccountSession::failed, this, [this](const NetVfs::Result &result) {
        closeSession();
        fail(result.error(), userErrorText(result.error(), Activity::StoredSecret), result.message());
    });
}

void NetVfsProbe::cancel()
{
    m_jobs.cancel();
    closeSession();
    if (busy())
        setState(Idle);
}

void NetVfsProbe::reset()
{
    m_jobs.cancel();
    closeSession();
    m_error = Error::None;
    m_errorText.clear();
    m_errorDetail.clear();
    m_identity = ServerIdentity();
    m_identityStatus = IdentityNotChecked;
    m_freeBytes = -1;
    setState(Idle);
}

Backend *NetVfsProbe::createBackend(const QString &provider)
{
    Result result;
    Backend *backend = BackendLoader::create(provider, &result);
    if (!backend)
        fail(Error::Unsupported, backendMissingText(), result.message());
    return backend;
}

void NetVfsProbe::startVerify(const ConnectionParams &params, const Credentials &credentials,
                              const QString &backupsPath)
{
    Backend *backend = createBackend(params.provider);
    if (!backend)
        return;
    qCDebug(lcNetVfsUi) << "Verifying" << params.host << backupsPath;
    setState(Verifying);
    auto outcome = std::make_shared<ProbeOutcome>();
    m_jobs.start([backend, params, credentials, backupsPath, outcome](CancelToken *token) {
        // The captured credentials wipe themselves when the job is released (SEC-5).
        std::unique_ptr<Backend> owned(backend);
        token->attach(backend);
        *outcome = runVerify(backend, params, credentials, backupsPath);
        token->detach();
    }, [this, outcome]() { finishVerify(*outcome); });
}

void NetVfsProbe::finishIdentify(const ProbeOutcome &outcome)
{
    m_identity = outcome.identity;
    if (!outcome.result.ok()) {
        fail(outcome.result.error(), userErrorText(outcome.result.error()), outcome.result.message());
        return;
    }
    m_identityStatus = identityStatusFor(outcome);
    setState(Identified);
    emit identified();
}

void NetVfsProbe::finishVerify(const ProbeOutcome &outcome)
{
    // The identity was checked unless the connection itself failed.
    const Error error = outcome.result.error();
    if (outcome.result.ok() || !outcome.identity.isEmpty() || error == Error::ServerIdentityChanged) {
        m_identity = outcome.identity;
        m_identityStatus = identityStatusFor(outcome);
    }
    if (!outcome.result.ok()) {
        fail(outcome.result.error(), userErrorText(outcome.result.error()), outcome.result.message());
        return;
    }
    m_freeBytes = outcome.freeBytes;
    setState(Verified);
    emit verified();
}

void NetVfsProbe::fail(Error error, const QString &text, const QString &detail)
{
    qCDebug(lcNetVfsUi) << "Probe failed:" << errorName(error) << detail;
    m_error = error;
    m_errorText = text;
    m_errorDetail = detail;
    setState(Failed);
    emit failed();
}

void NetVfsProbe::setState(State state)
{
    m_state = state;
    emit stateChanged();
}

void NetVfsProbe::closeSession()
{
    if (!m_session)
        return;
    AccountSession *session = m_session.data();
    m_session.clear();
    disconnect(session, nullptr, this, nullptr);
    session->releaseCredentials();
    session->deleteLater();
}

} // namespace NetVfsUi
