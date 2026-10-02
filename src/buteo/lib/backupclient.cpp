// SPDX-License-Identifier: LGPL-2.1-or-later
// Structure adapted from the Nextcloud backup plugin of sailfish-account-nextcloud
// (NextcloudBackupOperationClient, Syncer):
//   SPDX-FileCopyrightText: 2019 - 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2019 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#include "backupclient.h"
#include "accountsession.h"
#include "accountstore.h"
#include "backupservice.h"
#include "backupsteps.h"
#include "logging.h"

#include <Accounts/Manager>
#include <ProfileEngineDefs.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

#include <memory>

namespace NetVfs {

namespace {
// SPEC 3.4: profile key holding the local restore target.
const char RestoreFileKey[] = "sfos-backuprestore-file";
const char StatusUploading[] = "UploadingBackup";
const char StatusCanceled[] = "Canceled";
const char StatusError[] = "Error";
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

BackupClient::~BackupClient()
{
    shutdown();
}

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
    if (!m_service) {
        auto service = std::make_unique<BackupService>(QDBusConnection::sessionBus());
        service->setParent(this);
        m_service = service.release();
        connect(m_service, &BackupService::cloudBackupStatusChanged, this, &BackupClient::onCloudBackupStatusChanged);
        connect(m_service, &BackupService::cloudBackupError, this, &BackupClient::onCloudBackupError);
        connect(m_service, &BackupService::cloudRestoreStatusChanged, this, &BackupClient::onCloudRestoreStatusChanged);
        connect(m_service, &BackupService::cloudRestoreError, this, &BackupClient::onCloudRestoreError);
    }
    return true;
}

bool BackupClient::uninit()
{
    shutdown();
    return true;
}

void BackupClient::shutdown()
{
    delete m_job.data();   // cancels and waits
    if (m_running) {
        m_running = false;
        ++m_run;
        removeLocalArchive();
    }
    delete m_session.data();
}

bool BackupClient::startSync()
{
    if (m_accountId == 0 || !m_service || m_running)
        return false;

    ++m_run;
    m_running = true;
    m_aborted = false;
    m_waitingForArchive = false;
    m_archiveReady = false;
    m_override = Result();
    m_remoteDir.clear();
    m_archivePath.clear();
    m_seenPin.clear();
    m_listing.clear();

    delete m_session.data();
    m_session = m_sessionFactory ? m_sessionFactory(m_accountId, this) : AccountSession::open(m_accountId, this);
    connect(m_session.data(), &AccountSession::ready, this, &BackupClient::onSessionReady);
    connect(m_session.data(), &AccountSession::failed, this, &BackupClient::fail);
    qCDebug(lcNetVfsButeo) << "Starting" << iProfile.name() << "for account" << m_accountId;
    return true;
}

void BackupClient::onSessionReady()
{
    if (!m_running)
        return;
    if (const QString accountProvider = m_session->config().provider; accountProvider != m_provider) {
        fail(Result(Error::Internal, QStringLiteral("Account %1 is a %2 account, not %3")
                                         .arg(m_accountId).arg(accountProvider, m_provider)));
        return;
    }
    const quint64 run = m_run;
    m_service->backupFileDeviceId([this, run](const Result &result, const QString &deviceId) {
        if (run == m_run)
            onDeviceId(result, deviceId);
    });
}

void BackupClient::onDeviceId(const Result &result, const QString &deviceId)
{
    Result r = result;
    if (r.ok())
        r = BackupSteps::remoteDirectory(m_session->backupsPath(), deviceId, &m_remoteDir);   // B-2
    if (!r.ok()) {
        fail(r);
        return;
    }
    startOperation();
}

void BackupClient::startOperation()
{
    const QString dir = m_remoteDir;
    switch (m_operation) {
    case Operation::Backup:
        startJob([dir](Backend *backend) { return BackupSteps::preflight(backend, dir); },
                 &BackupClient::requestArchive);
        break;
    case Operation::BackupQuery: {
        QStringList *listing = &m_listing;   // written by the job only, read after it finished
        startJob([dir, listing](Backend *backend) { return BackupSteps::listBackups(backend, dir, listing); },
                 &BackupClient::reportBackups);
        break;
    }
    case Operation::BackupRestore: {
        const QString local = iProfile.key(QLatin1String(RestoreFileKey));
        if (local.isEmpty()) {
            fail(Result(Error::Internal, QStringLiteral("No backup file to restore for %1").arg(iProfile.name())));
            return;
        }
        startJob([dir, local](Backend *backend) { return BackupSteps::restoreBackup(backend, dir, local); },
                 &BackupClient::succeed);
        break;
    }
    }
}

void BackupClient::startJob(const NetworkJob::Body &body, Continuation next)
{
    m_next = next;
    auto job = std::make_unique<NetworkJob>(m_session->config().provider, m_session->params(),
                                            m_session->credentials(), body);
    job->setParent(this);
    connect(job.get(), &QThread::finished, this, &BackupClient::onJobFinished);
    m_job = job.release();
    m_job->start();
}

void BackupClient::onJobFinished()
{
    NetworkJob *job = m_job.data();
    if (!job || job != sender())
        return;
    m_job.clear();
    job->wait();
    const Result r = job->result();
    if (!job->seenIdentity().isEmpty())
        m_seenPin = job->seenIdentity().toPin();
    job->deleteLater();

    if (!m_running)
        return;
    if (m_aborted) {
        finish(Result(Error::Canceled));
        return;
    }
    if (!m_override.ok()) {
        finish(m_override);
        return;
    }
    if (!r.ok()) {
        finish(r);
        return;
    }
    (this->*m_next)();
}

void BackupClient::requestArchive()
{
    m_waitingForArchive = true;
    const quint64 run = m_run;
    m_service->createBackupForSyncProfile(iProfile.name(), [this, run](const Result &result, const QString &path) {
        if (run == m_run)
            onArchiveRequested(result, path);
        else
            removeArchive(path);   // the run ended while the request was pending
    });
}

void BackupClient::onArchiveRequested(const Result &result, const QString &path)
{
    if (!result.ok()) {
        fail(result);
        return;
    }
    m_archivePath = path;
    // The status signal may have overtaken the reply.
    if (m_archiveReady)
        startUpload();
}

void BackupClient::onCloudBackupStatusChanged(int accountId, const QString &status)
{
    if (m_operation != Operation::Backup || !m_running || accountId != m_accountId)
        return;
    qCDebug(lcNetVfsButeo) << "Backup status" << status;
    if (status == QLatin1String(StatusUploading)) {
        if (!m_waitingForArchive)
            return;
        m_archiveReady = true;
        if (!m_archivePath.isEmpty())
            startUpload();
    } else if (status == QLatin1String(StatusCanceled)) {
        fail(Result(Error::Canceled, QStringLiteral("The backup service canceled the backup")));
    } else if (status == QLatin1String(StatusError)) {
        fail(Result(Error::Internal, QStringLiteral("The backup service could not create the backup archive")));
    }
}

void BackupClient::onCloudBackupError(int accountId, const QString &error, const QString &errorString)
{
    if (m_operation != Operation::Backup || !m_running || accountId != m_accountId)
        return;
    fail(Result(Error::Internal, QStringLiteral("The backup service failed: %1 %2").arg(error, errorString)));
}

void BackupClient::startUpload()
{
    m_waitingForArchive = false;
    const QString local = m_archivePath;
    const QString dir = m_remoteDir;
    // A fresh connection: building the archive can take minutes (SPEC 8.4 step 5).
    startJob([local, dir](Backend *backend) { return BackupSteps::uploadArchive(backend, local, dir); },
             &BackupClient::succeed);
}

void BackupClient::reportBackups()
{
    const quint64 run = m_run;
    m_service->setCloudBackups(iProfile.name(), m_listing, [this, run](const Result &result) {
        if (run == m_run)
            finish(result);
    });
}

void BackupClient::onCloudRestoreStatusChanged(int accountId, const QString &status)
{
    if (m_operation != Operation::BackupRestore || !m_running || accountId != m_accountId)
        return;
    qCDebug(lcNetVfsButeo) << "Restore status" << status;
    if (status == QLatin1String(StatusCanceled))
        fail(Result(Error::Canceled, QStringLiteral("The backup service canceled the restore")));
    else if (status == QLatin1String(StatusError))
        fail(Result(Error::Internal, QStringLiteral("The backup service reported a restore error")));
}

void BackupClient::onCloudRestoreError(int accountId, const QString &error, const QString &errorString) const
{
    // Informational, as in the reference; the status signal ends the run.
    if (accountId == m_accountId)
        qCDebug(lcNetVfsButeo) << "Restore error from the backup service:" << error << errorString;
}

void BackupClient::succeed()
{
    finish(Result::success());
}

void BackupClient::abortSync(Sync::SyncStatus status)
{
    if (!m_running || m_aborted)
        return;
    qCDebug(lcNetVfsButeo) << "Abort requested, status" << status;
    m_aborted = true;
    m_abortCode = minorCodeForAbort(status);
    // B-4: cancel the in-flight call; the run finishes when the worker returns.
    if (m_job) {
        m_job->cancel();
        return;
    }
    finish(Result(Error::Canceled));
}

void BackupClient::fail(const Result &result)
{
    if (m_job) {
        if (m_override.ok())
            m_override = result;
        m_job->cancel();
        return;
    }
    finish(result);
}

void BackupClient::finish(const Result &result)
{
    if (!m_running)
        return;   // B-7: one result per run
    m_running = false;
    m_waitingForArchive = false;
    ++m_run;
    removeLocalArchive();
    if (m_session)
        m_session->releaseCredentials();   // SEC-5

    if (m_aborted) {
        report(m_abortCode, QStringLiteral("Sync aborted"));
    } else if (result.ok()) {
        report(Buteo::SyncResults::NO_ERROR, QString());
    } else {
        recordAttention(result);
        report(minorCodeFor(result.error()), result.toString());
    }
}

void BackupClient::recordAttention(const Result &result)
{
    const Attention attention = attentionForError(result.error());
    if (attention == Attention::None)
        return;
    if (!m_manager)
        m_manager = std::make_unique<Accounts::Manager>();
    const QString pin = attention == Attention::ServerIdentityChanged ? m_seenPin : QString();
    if (const Result stored = AccountStore(m_manager.get()).setAttention(m_accountId, attention, pin); !stored.ok())
        qCWarning(lcNetVfsButeo) << "Cannot record the attention state:" << stored.toString();
}

void BackupClient::removeLocalArchive()
{
    // SPEC 8.4 step 6, on success and on failure.
    removeArchive(m_archivePath);
    m_archivePath.clear();
}

void BackupClient::removeArchive(const QString &path)
{
    if (path.isEmpty())
        return;
    const QFileInfo archive(path);
    QFile::remove(archive.absoluteFilePath());
    QDir().rmdir(archive.absolutePath());   // only when now empty
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
