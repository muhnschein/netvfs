// SPDX-License-Identifier: LGPL-2.1-or-later
#include "secretsource.h"
#include "logging.h"
#include "secure.h"

#include <SignOn/AuthSession>
#include <SignOn/Error>
#include <SignOn/Identity>
#include <SignOn/SessionData>

namespace NetVfs {

namespace {
const char AuthMethod[] = "password";   // signond method and mechanism name
}

SecretSource::SecretSource(QObject *parent)
    : QObject(parent)
{
    qRegisterMetaType<NetVfs::Credentials>();
    qRegisterMetaType<NetVfs::Result>();
}

SecretSource::~SecretSource() = default;

SignonSecretSource::SignonSecretSource(QObject *parent)
    : SecretSource(parent)
{
}

SignonSecretSource::~SignonSecretSource()
{
    finish();
}

void SignonSecretSource::fetch(quint32 credentialsId)
{
    finish();
    if (credentialsId == 0) {
        noSecret(Result(Error::AuthFailed, QStringLiteral("The account has no stored credentials")));
        return;
    }

    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        noSecret(Result(Error::AuthFailed, QStringLiteral("The stored credentials are missing")));
        return;
    }
    m_session = m_identity->createSession(QLatin1String(AuthMethod));
    if (!m_session) {
        finish();
        emit failed(Result(Error::Internal, QStringLiteral("Cannot open a credentials session")));
        return;
    }
    connect(m_session.data(), &SignOn::AuthSession::response, this, &SignonSecretSource::onResponse);
    connect(m_session.data(), &SignOn::AuthSession::error, this, &SignonSecretSource::onError);

    SignOn::SessionData data;
    data.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_session->process(data, QLatin1String(AuthMethod));
}

void SignonSecretSource::onResponse(const SignOn::SessionData &data)
{
    QString secret = data.Secret();
    QByteArray bytes = secret.toUtf8();
    secureWipe(secret);
    const Credentials credentials(data.UserName(), bytes);
    secureWipe(bytes);
    finish();
    if (credentials.secret.isEmpty())
        noSecret(Result(Error::AuthFailed, QStringLiteral("The stored secret is empty")), credentials.userName);
    else
        emit fetched(credentials);
}

bool acceptsMissingSecret(const Result &lookup, bool secretOptional)
{
    return secretOptional && lookup.error() == Error::AuthFailed;
}

void SignonSecretSource::noSecret(const Result &lookup, const QString &userName)
{
    if (acceptsMissingSecret(lookup, secretOptional()))
        emit fetched(Credentials(userName, QByteArray()));
    else
        emit failed(lookup);
}

Result secretErrorFromSignon(int signonErrorType)
{
    // A-6: only an identity or secret that cannot be used is AuthFailed (and
    // thus flags the account, SPEC 6.4); a signond outage is not.
    switch (signonErrorType) {
    case SignOn::Error::PermissionDenied:          // signond's answer for an unknown identity
    case SignOn::Error::IdentityNotFound:
    case SignOn::Error::CredentialsNotAvailable:
    case SignOn::Error::MissingData:
    case SignOn::Error::InvalidCredentials:
    case SignOn::Error::NotAuthorized:
    case SignOn::Error::UserInteraction:           // the password plugin wants input: no usable secret
        return Result(Error::AuthFailed, QStringLiteral("The stored credentials cannot be used"));
    default:
        return Result(Error::Internal, QStringLiteral("The credentials service is not available"));
    }
}

void SignonSecretSource::onError(const SignOn::Error &error)
{
    qCWarning(lcNetVfsCore) << "Credentials lookup failed with signond error" << error.type();
    qCDebug(lcNetVfsCore) << "signond:" << error.message();
    finish();
    noSecret(secretErrorFromSignon(error.type()));
}

void SignonSecretSource::finish()
{
    if (m_identity) {
        if (m_session)
            m_identity->destroySession(m_session);
        m_identity->deleteLater();
    }
    m_identity = nullptr;
    m_session.clear();
}

} // namespace NetVfs
