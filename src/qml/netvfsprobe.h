// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_PROBE_H
#define NETVFS_QML_PROBE_H

#include "backendjobs.h"
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
    NetVfs::Result identityCheck;      // checkServerIdentity() against the pin
    qint64 freeBytes = -1;
};

// Phase 1 (SPEC 7.3 step 2, C-7): connect and report the server identity.
// No credentials are sent. The backend is disconnected afterwards.
ProbeOutcome runIdentify(NetVfs::Backend *backend, const NetVfs::ConnectionParams &params);
// Phase 2 (SPEC 7.2): establish() with the pin in params.options["host_key"]
// (SEC-1), then verifyAccess(): makePath, probe file, free space.
ProbeOutcome runVerify(NetVfs::Backend *backend, const NetVfs::ConnectionParams &params,
                       const NetVfs::Credentials &credentials, const QString &backupsPath);

// Asynchronous two-phase connection test for the account UI (SPEC 7.2).
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
    enum State { Idle, Identifying, Identified, Verifying, Verified, Failed };
    Q_ENUM(State)

    // Mirrors NetVfs::Error (SPEC 5.4).
    enum ErrorCode {
        NoError, Canceled, NetworkUnreachable, Timeout, ServerIdentityUnknown, ServerIdentityChanged,
        AuthFailed, SecurityPolicy, PermissionDenied, NotFound, AlreadyExists, NoSpace, Unsupported,
        ProtocolError, Internal
    };
    Q_ENUM(ErrorCode)

    // Result of comparing the identity seen by identify() with params.options.host_key.
    enum IdentityStatus { IdentityNotChecked, NoIdentity, IdentityUnknown, IdentityMatches, IdentityChanged };
    Q_ENUM(IdentityStatus)

    using SessionFactory = std::function<NetVfs::AccountSession *(int accountId, QObject *parent)>;

    explicit NetVfsProbe(QObject *parent = nullptr);
    ~NetVfsProbe() override;

    State state() const { return m_state; }
    bool busy() const { return m_state == Identifying || m_state == Verifying; }
    ErrorCode error() const { return static_cast<ErrorCode>(m_error); }
    QString errorText() const { return m_errorText; }
    QString errorDetail() const { return m_errorDetail; }
    QVariantMap serverIdentity() const;
    IdentityStatus identityStatus() const { return m_identityStatus; }
    qint64 freeBytes() const { return m_freeBytes; }

    // params: { provider, host, port, username, options: {...} } (Helpers::makeParams).
    Q_INVOKABLE void identify(const QVariantMap &params);
    // credentials: { username, secret }. The secret is wiped after use.
    Q_INVOKABLE void verify(const QVariantMap &params, const QVariantMap &credentials,
                            const QString &backupsPath);
    // Verifies a stored account with its stored secret (read through signond
    // by the core, never exposed to QML). A non-empty `pin` replaces the
    // stored host key, for the update flow after the user accepted a new one.
    Q_INVOKABLE void verifyAccount(int accountId, const QString &pin = QString());
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
                     const QString &backupsPath);
    void finishIdentify(const ProbeOutcome &outcome);
    void finishVerify(const ProbeOutcome &outcome);
    void fail(NetVfs::Error error, const QString &text, const QString &detail);
    void setState(State state);
    void closeSession();

    State m_state = Idle;
    NetVfs::Error m_error = NetVfs::Error::None;
    QString m_errorText;
    QString m_errorDetail;
    NetVfs::ServerIdentity m_identity;
    IdentityStatus m_identityStatus = IdentityNotChecked;
    qint64 m_freeBytes = -1;
    SessionFactory m_sessionFactory;
    QPointer<NetVfs::AccountSession> m_session;
    BackendJobs m_jobs;   // last member: destroyed (and joined) first
};

} // namespace NetVfsUi

#endif
