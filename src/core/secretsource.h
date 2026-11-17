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

class NETVFS_EXPORT SecretSource : public QObject
{
    Q_OBJECT
public:
    explicit SecretSource(QObject *parent = nullptr);
    ~SecretSource() override;

    virtual void fetch(quint32 credentialsId) = 0;

    // Account legitimately has no stored secret (secretOptional()): missing identity or empty
    // secret is then fetched() with empty secret, not AuthFailed. Set before fetch().
    void setSecretOptional(bool optional) { m_secretOptional = optional; }
    bool secretOptional() const { return m_secretOptional; }

Q_SIGNALS:
    void fetched(const NetVfs::Credentials &credentials);
    void failed(const NetVfs::Result &result);

private:
    bool m_secretOptional = false;
};

// signond implementation: password method, NoUserInteractionPolicy. Missing identity or empty
// secret is AuthFailed unless optional. A signond outage fails in both cases.
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
    void noSecret(const NetVfs::Result &lookup, const QString &userName = QString());

    SignOn::Identity *m_identity = nullptr;
    QPointer<SignOn::AuthSession> m_session;
};

NETVFS_EXPORT Result secretErrorFromSignon(int signonErrorType);

// Whether a lookup without usable secret still yields credentials: only for an optional secret,
// only when there is no secret (AuthFailed), never on an outage.
NETVFS_EXPORT bool acceptsMissingSecret(const Result &lookup, bool secretOptional);

}
Q_DECLARE_METATYPE(NetVfs::Credentials)
Q_DECLARE_METATYPE(NetVfs::Result)

#endif
