// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_SECRETSOURCE_H
#define NETVFS_SECRETSOURCE_H

#include "error.h"
#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>

namespace SignOn {
class Identity;
class AuthSession;
class Error;
class SessionData;
}

namespace NetVfs {

// Asynchronous access to an account's secret (SPEC C-2, A-6).
class NETVFS_EXPORT SecretSource : public QObject
{
    Q_OBJECT
public:
    explicit SecretSource(QObject *parent = nullptr);
    ~SecretSource() override;

    // Emits exactly one of fetched() or failed().
    virtual void fetch(quint32 credentialsId) = 0;

    // SPEC-v2 XA-7: the account legitimately has no stored secret
    // (secretOptional()): a missing identity or an empty secret is then
    // fetched() with an empty secret instead of AuthFailed. Set before fetch().
    void setSecretOptional(bool optional) { m_secretOptional = optional; }
    bool secretOptional() const { return m_secretOptional; }

Q_SIGNALS:
    void fetched(const NetVfs::Credentials &credentials);
    void failed(const NetVfs::Result &result);

private:
    bool m_secretOptional = false;
};

// signond implementation: password method, NoUserInteractionPolicy. A missing
// identity or an empty secret is AuthFailed (A-6), unless the secret is
// optional (XA-7). A signond outage stays a failure in both cases.
class NETVFS_EXPORT SignonSecretSource : public SecretSource
{
    Q_OBJECT
public:
    explicit SignonSecretSource(QObject *parent = nullptr);
    ~SignonSecretSource() override;

    void fetch(quint32 credentialsId) override;

private:
    void onResponse(const SignOn::SessionData &data);
    void onError(const SignOn::Error &error);
    void finish();
    // A-6 / XA-7: `lookup` says why there is no usable secret.
    void noSecret(const NetVfs::Result &lookup, const QString &userName = QString());

    SignOn::Identity *m_identity = nullptr;
    QPointer<SignOn::AuthSession> m_session;
};

// Maps a SignOn::Error type to the result of a secret lookup (A-6).
NETVFS_EXPORT Result secretErrorFromSignon(int signonErrorType);

// SPEC-v2 XA-7: whether a lookup that found no usable secret (`lookup`)
// still yields credentials: only for an optional secret, and only when the
// lookup failed because there is no secret (AuthFailed), never on an outage.
NETVFS_EXPORT bool acceptsMissingSecret(const Result &lookup, bool secretOptional);

} // namespace NetVfs

Q_DECLARE_METATYPE(NetVfs::Credentials)
Q_DECLARE_METATYPE(NetVfs::Result)

#endif
