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

Q_SIGNALS:
    void fetched(const NetVfs::Credentials &credentials);
    void failed(const NetVfs::Result &result);
};

// signond implementation: password method, NoUserInteractionPolicy. A missing
// identity or an empty secret is AuthFailed.
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

    SignOn::Identity *m_identity = nullptr;
    QPointer<SignOn::AuthSession> m_session;
};

} // namespace NetVfs

Q_DECLARE_METATYPE(NetVfs::Credentials)
Q_DECLARE_METATYPE(NetVfs::Result)

#endif
