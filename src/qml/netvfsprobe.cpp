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

static_assert(static_cast<int>(Error::Internal) == static_cast<int>(NetVfsProbe::ErrorCode::Internal),
              "NetVfsProbe::ErrorCode must mirror NetVfs::Error");
static_assert(static_cast<int>(Error::AuthFailed) == static_cast<int>(NetVfsProbe::ErrorCode::AuthFailed),
              "NetVfsProbe::ErrorCode must mirror NetVfs::Error");

namespace {
constexpr const char *HostKeyOption = "host_key";
constexpr const char *AuthInteractive = "interactive";

NetVfsProbe::IdentityStatus matchedStatus(const ProbeOutcome &outcome)
{
    using Status = NetVfsProbe::IdentityStatus;
    if (outcome.identity.isEmpty())
        return Status::NoIdentity;
    // XC-16: accepted without a pin because the system trusts the certificate.
    if (!outcome.pinned && outcome.identity.kind == ServerIdentity::Kind::TlsCertificate)
        return Status::IdentityTrusted;
    return Status::IdentityMatches;
}

NetVfsProbe::IdentityStatus identityStatusFor(const ProbeOutcome &outcome)
{
    using Status = NetVfsProbe::IdentityStatus;
    switch (outcome.identityCheck.error()) {
    case Error::None:
        return matchedStatus(outcome);
    case Error::ServerIdentityUnknown:
        return Status::IdentityUnknown;
    default:
        return Status::IdentityChanged;
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

AccountSession *openSession(int accountId, Service service, QObject *parent)
{
    return AccountSession::open(accountId, service, parent);
}

// Interactive sign-in cannot be answered here: connect and check the identity only.
void verifyIdentityOnly(Backend *backend, const ConnectionParams &params, ProbeOutcome *outcome)
{
    outcome->result = backend->connect(params, &outcome->identity);
    if (!outcome->result.ok())
        return;
    outcome->identityCheck = identityCheckFor(outcome->identity, params);
    outcome->result = outcome->identityCheck;
    backend->disconnect();
}

Activity verifyActivity(const ProbeOutcome &outcome, Service service)
{
    if (service == Service::Files)
        return Activity::Browse;
    return outcome.refusedByPolicy ? Activity::ServicePolicy : Activity::Connect;
}
} // namespace

Result identityCheckFor(const ServerIdentity &seen, const ConnectionParams &params)
{
    const QString pin = params.option(QLatin1String(HostKeyOption));
    const Result r = checkServerIdentity(seen, pin);
    if (r.ok() && pin.isEmpty() && seen.kind == ServerIdentity::Kind::TlsCertificate
            && params.flag(QLatin1String(OptionKeys::PinTrusted)))
        return Result(Error::ServerIdentityUnknown, QStringLiteral("The certificate is to be pinned (pin_trusted)"));
    return r;
}

ProbeOutcome runIdentify(Backend *backend, const ConnectionParams &params)
{
    ProbeOutcome outcome;
    outcome.pinned = !params.option(QLatin1String(HostKeyOption)).isEmpty();
    outcome.result = backend->connect(params, &outcome.identity);
    if (outcome.result.ok()) {
        outcome.identityCheck = identityCheckFor(outcome.identity, params);
        backend->disconnect();
    }
    return outcome;
}

ProbeOutcome runVerify(Backend *backend, const ConnectionParams &params, const Credentials &credentials,
                       const QString &folder, Service service)
{
    ProbeOutcome outcome;
    outcome.pinned = !params.option(QLatin1String(HostKeyOption)).isEmpty();
    outcome.result = checkServicePolicy(params, service);   // XA-4, before anything is sent
    if (!outcome.result.ok()) {
        outcome.refusedByPolicy = true;
        return outcome;
    }
    if (params.option(QLatin1String(OptionKeys::AuthMode)) == QLatin1String(AuthInteractive)) {
        verifyIdentityOnly(backend, params, &outcome);
        return outcome;
    }
    outcome.result = establish(backend, params, credentials, &outcome.identity);
    outcome.identityCheck = identityCheckFor(outcome.identity, params);
    if (outcome.result.ok()) {
        // SPEC-v2-review 2.19: Files never writes (read-only shares, guests).
        outcome.result = service == Service::Backup ? verifyAccess(backend, folder, &outcome.freeBytes)
                                                    : verifyBrowseAccess(backend, folder, &outcome.freeBytes);
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
    setState(State::Identifying);
    auto outcome = std::make_shared<ProbeOutcome>();
    m_jobs.start([backend, params, outcome](CancelToken *token) {
        std::unique_ptr<Backend> owned(backend);
        token->attach(backend);
        *outcome = runIdentify(backend, params);
        token->detach();
    }, [this, outcome]() { finishIdentify(*outcome); });
}

void NetVfsProbe::verify(const QVariantMap &paramsMap, const QVariantMap &credentialsMap,
                         const QString &folder, const QString &serviceId)
{
    reset();
    Service service = Service::Backup;
    if (!serviceFromId(serviceId, &service)) {
        fail(Error::Internal, userErrorText(Error::Internal), QStringLiteral("Unknown service ") + serviceId);
        return;
    }
    const ConnectionParams params = paramsFromVariant(paramsMap);
    const Credentials credentials = credentialsFromVariant(credentialsMap, params.username);
    startVerify(params, credentials, folder, service);
}

void NetVfsProbe::verifyAccount(int accountId, const QVariantMap &pinOptions, const QString &serviceId)
{
    reset();
    Service service = Service::Backup;
    if (!serviceFromId(serviceId, &service)) {
        fail(Error::Internal, userErrorText(Error::Internal), QStringLiteral("Unknown service ") + serviceId);
        return;
    }
    setState(State::Verifying);
    AccountSession *session = m_sessionFactory(accountId, service, this);
    m_session = session;
    connect(session, &AccountSession::ready, this, [this, session, pinOptions, service]() {
        ConnectionParams params = session->params();
        for (auto it = pinOptions.constBegin(); it != pinOptions.constEnd(); ++it)
            params.options.insert(it.key(), it.value());
        const Credentials credentials = session->credentials();
        const QString folder = service == Service::Backup ? session->backupsPath() : session->filesRoot();
        closeSession();
        startVerify(params, credentials, folder, service);
    });
    connect(session, &AccountSession::failed, this, [this, service](const NetVfs::Result &result) {
        closeSession();
        // XA-4: the session refuses a configuration before reading the secret.
        Activity activity = Activity::StoredSecret;
        if (result.error() == Error::SecurityPolicy)
            activity = service == Service::Backup ? Activity::ServicePolicy : Activity::Connect;
        fail(result.error(), userErrorText(result.error(), activity), result.message());
    });
}

void NetVfsProbe::cancel()
{
    m_jobs.cancel();
    closeSession();
    if (busy())
        setState(State::Idle);
}

void NetVfsProbe::reset()
{
    m_jobs.cancel();
    closeSession();
    m_error = Error::None;
    m_errorText.clear();
    m_errorDetail.clear();
    m_identity = ServerIdentity();
    m_identityStatus = IdentityStatus::IdentityNotChecked;
    m_freeBytes = -1;
    setState(State::Idle);
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
                              const QString &folder, Service service)
{
    Backend *backend = createBackend(params.provider);
    if (!backend)
        return;
    qCDebug(lcNetVfsUi) << "Verifying" << params.host << serviceId(service) << folder;
    setState(State::Verifying);
    auto outcome = std::make_shared<ProbeOutcome>();
    // A backup verify creates the backups folder the way backups do (S-20).
    const ConnectionParams serviceParams = service == Service::Backup ? withBackupDirMode(params) : params;
    m_jobs.start([backend, serviceParams, credentials, folder, service, outcome](CancelToken *token) {
        // The captured credentials wipe themselves when the job is released (SEC-5).
        std::unique_ptr<Backend> owned(backend);
        token->attach(backend);
        *outcome = runVerify(backend, serviceParams, credentials, folder, service);
        token->detach();
    }, [this, outcome, service]() { finishVerify(*outcome, service); });
}

void NetVfsProbe::finishIdentify(const ProbeOutcome &outcome)
{
    m_identity = outcome.identity;
    if (!outcome.result.ok()) {
        fail(outcome.result.error(), userErrorText(outcome.result.error()), outcome.result.message());
        return;
    }
    m_identityStatus = identityStatusFor(outcome);
    setState(State::Identified);
    emit identified();
}

void NetVfsProbe::finishVerify(const ProbeOutcome &outcome, Service service)
{
    // The identity was checked unless the connection itself failed.
    if (const Error error = outcome.result.error();
            outcome.result.ok() || !outcome.identity.isEmpty() || error == Error::ServerIdentityChanged) {
        m_identity = outcome.identity;
        m_identityStatus = identityStatusFor(outcome);
    }
    if (!outcome.result.ok()) {
        fail(outcome.result.error(), userErrorText(outcome.result.error(), verifyActivity(outcome, service)),
             outcome.result.message());
        return;
    }
    m_freeBytes = outcome.freeBytes;
    setState(State::Verified);
    emit verified();
}

void NetVfsProbe::fail(Error error, const QString &text, const QString &detail)
{
    qCDebug(lcNetVfsUi) << "Probe failed:" << errorName(error) << detail;
    m_error = error;
    m_errorText = text;
    m_errorDetail = detail;
    setState(State::Failed);
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
