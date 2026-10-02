// SPDX-License-Identifier: LGPL-2.1-or-later
// Flow adapted from the Nextcloud backup plugin of sailfish-account-nextcloud (Syncer):
//   SPDX-FileCopyrightText: 2019 - 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2019 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#include "backuprun.h"
#include "accountsession.h"
#include "accountstore.h"
#include "backupservice.h"
#include "backupsteps.h"
#include "logging.h"
#include "probe.h"

#include <Accounts/Manager>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QPointer>

namespace NetVfs {

namespace {
const char StatusUploading[] = "UploadingBackup";
const char StatusCanceled[] = "Canceled";
const char StatusError[] = "Error";

// SPEC 8.4 step 6: the archive and its directory, when that is now empty.
void removeArchive(const QString &path)
{
    if (path.isEmpty())
        return;
    const QFileInfo archive(path);
    QFile::remove(archive.absoluteFilePath());
    QDir().rmdir(archive.absolutePath());   // only when now empty
}
} // namespace

BackupRun::BackupRun(const RunSpec &spec, BackupService *service, const SessionFactory &sessionFactory)
    : m_spec(spec)
    , m_service(service)
    , m_sessionFactory(sessionFactory)
{
    connect(m_service, &BackupService::cloudBackupStatusChanged, this, &BackupRun::onCloudBackupStatusChanged);
    connect(m_service, &BackupService::cloudBackupError, this, &BackupRun::onCloudBackupError);
    connect(m_service, &BackupService::cloudRestoreStatusChanged, this, &BackupRun::onCloudRestoreStatusChanged);
    connect(m_service, &BackupService::cloudRestoreError, this, &BackupRun::onCloudRestoreError);
}

BackupRun::~BackupRun()
{
    m_job.reset();   // cancels and waits
    if (m_running)
        removeLocalArchive();
}

void BackupRun::start()
{
    m_running = true;
    m_session.reset(m_sessionFactory ? m_sessionFactory(m_spec.accountId, nullptr)
                                     : AccountSession::open(m_spec.accountId, Service::Backup, nullptr));
    connect(m_session.get(), &AccountSession::ready, this, &BackupRun::onSessionReady);
    connect(m_session.get(), &AccountSession::failed, this, &BackupRun::fail);
    qCDebug(lcNetVfsButeo) << "Starting" << m_spec.profileName << "for account" << m_spec.accountId;
}

void BackupRun::onSessionReady()
{
    if (!m_running)
        return;
    if (const QString accountProvider = m_session->config().provider; accountProvider != m_spec.provider) {
        fail(Result(Error::Internal, QStringLiteral("Account %1 is a %2 account, not %3")
                                         .arg(m_spec.accountId).arg(accountProvider, m_spec.provider)));
        return;
    }
    const QPointer<BackupRun> self(this);
    m_service->backupFileDeviceId([self](const Result &result, const QString &deviceId) {
        if (self)
            self->onDeviceId(result, deviceId);
    });
}

void BackupRun::onDeviceId(const Result &result, const QString &deviceId)
{
    if (!m_running)
        return;
    Result r = result;
    if (r.ok())
        r = BackupSteps::remoteDirectory(m_session->backupsPath(), deviceId, &m_remoteDir);   // B-2
    if (!r.ok()) {
        fail(r);
        return;
    }
    startOperation();
}

void BackupRun::startOperation()
{
    const QString dir = m_remoteDir;
    switch (m_spec.operation) {
    case BackupOperation::Backup:
        startJob([dir](Backend *backend) { return BackupSteps::preflight(backend, dir); },
                 [this]() { requestArchive(); });
        break;
    case BackupOperation::BackupQuery: {
        QStringList *listing = &m_listing;   // written by the job only, read after it finished
        startJob([dir, listing](Backend *backend) { return BackupSteps::listBackups(backend, dir, listing); },
                 [this]() { reportBackups(); });
        break;
    }
    case BackupOperation::BackupRestore: {
        const QString local = m_spec.restoreFile;
        if (local.isEmpty()) {
            fail(Result(Error::Internal, QStringLiteral("No backup file to restore for %1").arg(m_spec.profileName)));
            return;
        }
        startJob([dir, local](Backend *backend) { return BackupSteps::restoreBackup(backend, dir, local); },
                 [this]() { finish(Result::success()); });
        break;
    }
    }
}

void BackupRun::startJob(const NetworkJob::Body &body, const std::function<void()> &next)
{
    m_next = next;
    m_job = std::make_unique<NetworkJob>(m_session->config().provider, withBackupDirMode(m_session->params()),
                                         m_session->credentials(), body);
    connect(m_job.get(), &QThread::finished, this, &BackupRun::onJobFinished);
    m_job->start();
}

void BackupRun::onJobFinished()
{
    if (!m_job || m_job.get() != sender())
        return;
    // Queued from the worker: the thread has ended, so the job can go now.
    const std::unique_ptr<NetworkJob> job = std::move(m_job);
    job->wait();
    const Result r = job->result();
    if (!job->seenIdentity().isEmpty())
        m_seenPin = job->seenIdentity().toPin();

    if (!m_running)
        return;
    if (m_aborted)
        finish(Result(Error::Canceled));
    else if (!m_override.ok())
        finish(m_override);
    else if (!r.ok())
        finish(r);
    else
        m_next();
}

void BackupRun::requestArchive()
{
    m_waitingForArchive = true;
    const QPointer<BackupRun> self(this);
    m_service->createBackupForSyncProfile(m_spec.profileName, [self](const Result &result, const QString &path) {
        if (self && self->m_running)
            self->onArchiveRequested(result, path);
        else
            removeArchive(path);   // the run ended while the request was pending
    });
}

void BackupRun::onArchiveRequested(const Result &result, const QString &path)
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

void BackupRun::onCloudBackupStatusChanged(int accountId, const QString &status)
{
    if (m_spec.operation != BackupOperation::Backup || !m_running || accountId != m_spec.accountId)
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

void BackupRun::onCloudBackupError(int accountId, const QString &error, const QString &errorString)
{
    if (m_spec.operation != BackupOperation::Backup || !m_running || accountId != m_spec.accountId)
        return;
    fail(Result(Error::Internal, QStringLiteral("The backup service failed: %1 %2").arg(error, errorString)));
}

void BackupRun::startUpload()
{
    m_waitingForArchive = false;
    const QString local = m_archivePath;
    const QString dir = m_remoteDir;
    // A fresh connection: building the archive can take minutes (SPEC 8.4 step 5).
    startJob([local, dir](Backend *backend) { return BackupSteps::uploadArchive(backend, local, dir); },
             [this]() { finish(Result::success()); });
}

void BackupRun::reportBackups()
{
    const QPointer<BackupRun> self(this);
    m_service->setCloudBackups(m_spec.profileName, m_listing, [self](const Result &result) {
        if (self)
            self->finish(result);
    });
}

void BackupRun::onCloudRestoreStatusChanged(int accountId, const QString &status)
{
    if (m_spec.operation != BackupOperation::BackupRestore || !m_running || accountId != m_spec.accountId)
        return;
    qCDebug(lcNetVfsButeo) << "Restore status" << status;
    if (status == QLatin1String(StatusCanceled))
        fail(Result(Error::Canceled, QStringLiteral("The backup service canceled the restore")));
    else if (status == QLatin1String(StatusError))
        fail(Result(Error::Internal, QStringLiteral("The backup service reported a restore error")));
}

void BackupRun::onCloudRestoreError(int accountId, const QString &error, const QString &errorString) const
{
    // Informational, as in the reference; the status signal ends the run.
    if (accountId == m_spec.accountId)
        qCDebug(lcNetVfsButeo) << "Restore error from the backup service:" << error << errorString;
}

void BackupRun::abort()
{
    if (!m_running || m_aborted)
        return;
    m_aborted = true;
    // B-4: cancel the in-flight call; the run finishes when the worker returns.
    if (m_job) {
        m_job->cancel();
        return;
    }
    finish(Result(Error::Canceled));
}

void BackupRun::fail(const Result &result)
{
    if (m_job) {
        if (m_override.ok())
            m_override = result;
        m_job->cancel();
        return;
    }
    finish(result);
}

void BackupRun::finish(const Result &result)
{
    if (!m_running)
        return;   // B-7: one result per run
    m_running = false;
    m_waitingForArchive = false;
    removeLocalArchive();
    if (m_session)
        m_session->releaseCredentials();   // SEC-5
    if (!m_aborted && !result.ok())
        recordAttention(result);
    emit finished(m_aborted ? Result(Error::Canceled) : result);
}

void BackupRun::recordAttention(const Result &result)
{
    const Attention attention = attentionForError(result.error());
    if (attention == Attention::None)
        return;
    if (!m_manager)
        m_manager = std::make_unique<Accounts::Manager>();
    const QString pin = attention == Attention::ServerIdentityChanged ? m_seenPin : QString();
    if (const Result stored = AccountStore(m_manager.get()).setAttention(m_spec.accountId, Service::Backup, attention, pin); !stored.ok())
        qCWarning(lcNetVfsButeo) << "Cannot record the attention state:" << stored.toString();
}

void BackupRun::removeLocalArchive()
{
    // SPEC 8.4 step 6, on success and on failure.
    removeArchive(m_archivePath);
    m_archivePath.clear();
}

} // namespace NetVfs
