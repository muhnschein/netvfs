// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_PROBE_H
#define NETVFS_QML_PROBE_H

#include "backendjobs.h"
#include "servicepolicy.h"
#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QPointer>
#include <QtCore/QVariantMap>

#include <functional>

namespace NetVfs {
class AccountSession;
}

namespace NetVfsUi {

// Outcome of one probe operation, produced on the worker thread.
struct ProbeOutcome {
    NetVfs::Result result;
    NetVfs::ServerIdentity identity;
    NetVfs::Result identityCheck;
    qint64 freeBytes = -1;
    bool refusedByPolicy = false;
};

// checkServerIdentity() against the pin in params.options["host_key"].
NetVfs::Result identityCheckFor(const NetVfs::ServerIdentity &seen, const NetVfs::ConnectionParams &params);

// Phase 1: connect and report the server identity. No credentials sent; the backend is disconnected
// afterwards.
ProbeOutcome runIdentify(NetVfs::Backend *backend, const NetVfs::ConnectionParams &params);
// Phase 2: the configuration is first checked against the service (refused without connecting).
// Then establish() with the pin in params.options["host_key"] and:
//   Backup: verifyAccess(): makePath, probe file, free space
//   Files: verifyBrowseAccess(): stat of the start folder, nothing written
// auth_mode=interactive needs a person: only connection and identity are checked.
ProbeOutcome runVerify(NetVfs::Backend *backend, const NetVfs::ConnectionParams &params,
                       const NetVfs::Credentials &credentials, const QString &folder, NetVfs::Service service);

// Asynchronous two-phase connection test for the account UI.
class NetVfsProbe : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(NetVfsProbe)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(ErrorCode error READ error NOTIFY stateChanged)
    Q_PROPERTY(QString errorText READ errorText NOTIFY stateChanged)
    Q_PROPERTY(QString errorDetail READ errorDetail NOTIFY stateChanged)
    Q_PROPERTY(QVariantMap serverIdentity READ serverIdentity NOTIFY stateChanged)
    Q_PROPERTY(IdentityStatus identityStatus READ identityStatus NOTIFY stateChanged)
    Q_PROPERTY(qint64 freeBytes READ freeBytes NOTIFY stateChanged)

public:
    enum class State { Idle, Identifying, Identified, Verifying, Verified, Failed };
    Q_ENUM(State)

    // Mirrors NetVfs::Error.
    enum class ErrorCode {
        NoError, Canceled, NetworkUnreachable, Timeout, ServerIdentityUnknown, ServerIdentityChanged,
        AuthFailed, SecurityPolicy, PermissionDenied, NotFound, AlreadyExists, NoSpace, Unsupported,
        ProtocolError, Internal
    };
    Q_ENUM(ErrorCode)

    // Result of comparing the identity seen by identify() with params.options.host_key.
    enum class IdentityStatus { IdentityNotChecked, NoIdentity, IdentityUnknown, IdentityMatches, IdentityChanged };
    Q_ENUM(IdentityStatus)

    using SessionFactory = std::function<NetVfs::AccountSession *(int accountId, NetVfs::Service service,
                                                                  QObject *parent)>;

    explicit NetVfsProbe(QObject *parent = nullptr);
    ~NetVfsProbe() override;

    State state() const { return m_state; }
    bool busy() const { return m_state == State::Identifying || m_state == State::Verifying; }
    ErrorCode error() const { return static_cast<ErrorCode>(m_error); }
    QString errorText() const { return m_errorText; }
    QString errorDetail() const { return m_errorDetail; }
    QVariantMap serverIdentity() const;
    IdentityStatus identityStatus() const { return m_identityStatus; }
    qint64 freeBytes() const { return m_freeBytes; }

    // params: { provider, host, port, username, options: {...} } (Helpers::makeParams).
    Q_INVOKABLE void identify(const QVariantMap &params);
    // credentials: { username, secret }; secret wiped after use. service: "backup" (folder =
    // backups folder) or "files" (folder = start folder).
    Q_INVOKABLE void verify(const QVariantMap &params, const QVariantMap &credentials,
                            const QString &folder, const QString &service = QStringLiteral("backup"));
    // Verifies a stored account with its stored secret (read through signond by the core, never
    // exposed to QML) for `service`. Non-empty `pinOptions` replace the stored pin, for the update
    // flow after the user accepted a new identity.
    Q_INVOKABLE void verifyAccount(int accountId, const QVariantMap &pinOptions = QVariantMap(),
                                   const QString &service = QStringLiteral("backup"));
    Q_INVOKABLE void cancel();
    Q_INVOKABLE void reset();

    // Tests replace how stored accounts are opened.
    void setSessionFactory(const SessionFactory &factory) { m_sessionFactory = factory; }

Q_SIGNALS:
    void stateChanged();
    void identified();
    void verified();
    void failed();

private:
    NetVfs::Backend *createBackend(const QString &provider);
    void startVerify(const NetVfs::ConnectionParams &params, const NetVfs::Credentials &credentials,
                     const QString &folder, NetVfs::Service service);
    void finishIdentify(const ProbeOutcome &outcome);
    void finishVerify(const ProbeOutcome &outcome, NetVfs::Service service);
    void fail(NetVfs::Error error, const QString &text, const QString &detail);
    void setState(State state);
    void closeSession();

    State m_state = State::Idle;
    NetVfs::Error m_error = NetVfs::Error::None;
    QString m_errorText;
    QString m_errorDetail;
    NetVfs::ServerIdentity m_identity;
    IdentityStatus m_identityStatus = IdentityStatus::IdentityNotChecked;
    qint64 m_freeBytes = -1;
    SessionFactory m_sessionFactory;
    QPointer<NetVfs::AccountSession> m_session;
    BackendJobs m_jobs;
};

}
#endif
