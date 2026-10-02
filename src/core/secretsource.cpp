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
const char PasswordMethod[] = "password";
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
        emit failed(Result(Error::AuthFailed, QStringLiteral("The account has no stored credentials")));
        return;
    }

    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        emit failed(Result(Error::AuthFailed, QStringLiteral("The stored credentials are missing")));
        return;
    }
    m_session = m_identity->createSession(QLatin1String(PasswordMethod));
    if (!m_session) {
        finish();
        emit failed(Result(Error::Internal, QStringLiteral("Cannot open a credentials session")));
        return;
    }
    connect(m_session.data(), &SignOn::AuthSession::response, this, &SignonSecretSource::onResponse);
    connect(m_session.data(), &SignOn::AuthSession::error, this, &SignonSecretSource::onError);

    SignOn::SessionData data;
    data.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_session->process(data, QLatin1String(PasswordMethod));
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
        emit failed(Result(Error::AuthFailed, QStringLiteral("The stored secret is empty")));
    else
        emit fetched(credentials);
}

void SignonSecretSource::onError(const SignOn::Error &error)
{
    qCWarning(lcNetVfsCore) << "Credentials lookup failed:" << error.type() << error.message();
    finish();
    emit failed(Result(Error::AuthFailed, QStringLiteral("The stored credentials cannot be read")));
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
