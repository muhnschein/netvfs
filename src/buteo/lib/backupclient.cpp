// SPDX-License-Identifier: LGPL-2.1-or-later
// Structure adapted from the Nextcloud backup plugin of sailfish-account-nextcloud
// (NextcloudBackupOperationClient):
//   SPDX-FileCopyrightText: 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2020 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#include "backupclient.h"
#include "backupservice.h"
#include "logging.h"

#include <ProfileEngineDefs.h>

namespace NetVfs {

namespace {
// SPEC 3.4: profile key holding the local restore target.
const char RestoreFileKey[] = "sfos-backuprestore-file";
} // namespace

BackupClient::BackupClient(const QString &provider, Operation operation, const QString &pluginName,
                           const Buteo::SyncProfile &profile, Buteo::PluginCbInterface *cbInterface,
                           const SessionFactory &sessionFactory)
    : Buteo::ClientPlugin(pluginName, profile, cbInterface)
    , m_provider(provider)
    , m_operation(operation)
    , m_sessionFactory(sessionFactory)
{
}

BackupClient::~BackupClient() = default;

QString BackupClient::operationName() const
{
    switch (m_operation) {
    case Operation::Backup:
        return QStringLiteral("Backup");
    case Operation::BackupQuery:
        return QStringLiteral("BackupQuery");
    case Operation::BackupRestore:
        break;
    }
    return QStringLiteral("BackupRestore");
}

bool BackupClient::init()
{
    // B-1
    m_accountId = iProfile.key(Buteo::KEY_ACCOUNT_ID).toInt();
    if (m_accountId <= 0) {
        qCCritical(lcNetVfsButeo) << "Profile" << iProfile.name() << "does not specify" << Buteo::KEY_ACCOUNT_ID;
        m_accountId = 0;
        return false;
    }
    if (!m_service)
        m_service = std::make_unique<BackupService>(QDBusConnection::sessionBus());
    return true;
}

bool BackupClient::uninit()
{
    // Stops a run without a result; its local archive goes with it.
    m_run.reset();
    return true;
}

bool BackupClient::startSync()
{
    if (m_accountId == 0 || !m_service || isRunning())
        return false;

    RunSpec spec;
    spec.provider = m_provider;
    spec.operation = m_operation;
    spec.accountId = m_accountId;
    spec.profileName = iProfile.name();
    spec.restoreFile = iProfile.key(QLatin1String(RestoreFileKey));

    m_aborted = false;
    m_run = std::make_unique<BackupRun>(spec, m_service.get(), m_sessionFactory);
    connect(m_run.get(), &BackupRun::finished, this, &BackupClient::onRunFinished);
    m_run->start();
    return true;
}

void BackupClient::abortSync(Sync::SyncStatus status)
{
    if (!isRunning() || m_aborted)
        return;
    qCDebug(lcNetVfsButeo) << "Abort requested, status" << status;
    m_aborted = true;
    m_abortCode = minorCodeForAbort(status);
    m_run->abort();
}

void BackupClient::onRunFinished(const Result &result)
{
    if (m_aborted)
        report(m_abortCode, QStringLiteral("Sync aborted"));
    else if (result.ok())
        report(Buteo::SyncResults::NO_ERROR, QString());
    else
        report(minorCodeFor(result.error()), result.toString());
}

void BackupClient::report(Buteo::SyncResults::MinorCode code, const QString &message)
{
    if (code == Buteo::SyncResults::NO_ERROR) {
        qCDebug(lcNetVfsButeo) << iProfile.name() << "succeeded";
        m_results = Buteo::SyncResults(QDateTime::currentDateTimeUtc(), Buteo::SyncResults::SYNC_RESULT_SUCCESS,
                                       Buteo::SyncResults::NO_ERROR);
        emit success(getProfileName(), message);
        return;
    }
    // The message may name paths; those are for debug output only (C-17).
    qCWarning(lcNetVfsButeo) << iProfile.name() << "failed with code" << code;
    qCDebug(lcNetVfsButeo) << message;
    m_results = Buteo::SyncResults(iProfile.lastSuccessfulSyncTime(), Buteo::SyncResults::SYNC_RESULT_FAILED, code);
    emit error(getProfileName(), message, code);
}

bool BackupClient::cleanUp()
{
    // B-6: called after the account was deleted. Backups stay on the server.
    qCDebug(lcNetVfsButeo) << "Account removed; server files are kept";
    return true;
}

Buteo::SyncResults BackupClient::getSyncResults() const
{
    return m_results;
}

void BackupClient::connectivityStateChanged(Sync::ConnectivityType type, bool state)
{
    // B-5: a LAN server does not need internet connectivity; socket errors
    // and timeouts end a run that really lost its server.
    qCDebug(lcNetVfsButeo) << "Ignoring connectivity change" << type << state;
}

Buteo::SyncResults::MinorCode BackupClient::minorCodeFor(Error error)
{
    switch (error) {
    case Error::None:
        return Buteo::SyncResults::NO_ERROR;
    case Error::Canceled:
        return Buteo::SyncResults::ABORTED;
    case Error::NetworkUnreachable:
    case Error::Timeout:
        return Buteo::SyncResults::CONNECTION_ERROR;
    case Error::AuthFailed:
    case Error::ServerIdentityChanged:
    case Error::ServerIdentityUnknown:
        return Buteo::SyncResults::AUTHENTICATION_FAILURE;
    default:
        return Buteo::SyncResults::INTERNAL_ERROR;
    }
}

Buteo::SyncResults::MinorCode BackupClient::minorCodeForAbort(Sync::SyncStatus status)
{
    switch (status) {
    case Sync::SYNC_ERROR:              // msyncd: internet connectivity lost
    case Sync::SYNC_CONNECTION_ERROR:
        return Buteo::SyncResults::CONNECTION_ERROR;
    case Sync::SYNC_AUTHENTICATION_FAILURE:
        return Buteo::SyncResults::AUTHENTICATION_FAILURE;
    case Sync::SYNC_DATABASE_FAILURE:
        return Buteo::SyncResults::DATABASE_FAILURE;
    case Sync::SYNC_PLUGIN_ERROR:
        return Buteo::SyncResults::PLUGIN_ERROR;
    case Sync::SYNC_PLUGIN_TIMEOUT:
        return Buteo::SyncResults::PLUGIN_TIMEOUT;
    default:
        return Buteo::SyncResults::ABORTED;
    }
}

} // namespace NetVfs
