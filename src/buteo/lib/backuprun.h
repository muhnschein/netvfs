// SPDX-License-Identifier: LGPL-2.1-or-later
// Flow adapted from the Nextcloud backup plugin of sailfish-account-nextcloud (Syncer):
//   SPDX-FileCopyrightText: 2019 - 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2019 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#ifndef NETVFS_BUTEO_BACKUPRUN_H
#define NETVFS_BUTEO_BACKUPRUN_H

#include "networkjob.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>

#include <functional>
#include <memory>

namespace Accounts {
class Manager;
}

namespace NetVfs {

class AccountSession;
class BackupService;

enum class BackupOperation { Backup, BackupQuery, BackupRestore };

// How a run opens its account session (caller-owned result); empty means
// AccountSession::open() (accounts database and signond).
using SessionFactory = std::function<AccountSession *(int accountId, QObject *parent)>;

// What a run works on.
struct RunSpec {
    QString provider;
    BackupOperation operation = BackupOperation::Backup;
    int accountId = 0;
    QString profileName;
    QString restoreFile;     // BackupRestore: the local target (profile key sfos-backuprestore-file)
};

// One run of a backup operation (SPEC 8.4 to 8.6) on the plugin thread.
// Network work runs in NetworkJobs (B-3). Emits finished() exactly once
// (B-7); after that the run is inert.
class BackupRun : public QObject
{
    Q_OBJECT
public:
    BackupRun(const RunSpec &spec, BackupService *service, const SessionFactory &sessionFactory);
    // Stops the worker and removes a local archive of an unfinished run.
    ~BackupRun() override;
    Q_DISABLE_COPY(BackupRun)

    void start();
    // B-4: cancels the in-flight call; finished(Canceled) follows once the
    // worker returns. No attention state is recorded for an aborted run.
    void abort();
    bool isRunning() const { return m_running; }

Q_SIGNALS:
    void finished(const NetVfs::Result &result);

private:
    void onSessionReady();
    void onDeviceId(const Result &result, const QString &deviceId);
    void startOperation();
    void startJob(const NetworkJob::Body &body, const std::function<void()> &next);
    void onJobFinished();

    void requestArchive();
    void onArchiveRequested(const Result &result, const QString &path);
    void onCloudBackupStatusChanged(int accountId, const QString &status);
    void onCloudBackupError(int accountId, const QString &error, const QString &errorString);
    void startUpload();
    void reportBackups();
    void onCloudRestoreStatusChanged(int accountId, const QString &status);
    void onCloudRestoreError(int accountId, const QString &error, const QString &errorString) const;

    void fail(const Result &result);
    void finish(const Result &result);
    void recordAttention(const Result &result);
    void removeLocalArchive();

    const RunSpec m_spec;
    BackupService *const m_service;
    const SessionFactory m_sessionFactory;
    std::unique_ptr<AccountSession> m_session;
    std::unique_ptr<NetworkJob> m_job;
    std::function<void()> m_next;      // after a successful job
    std::unique_ptr<Accounts::Manager> m_manager;

    bool m_running = false;
    bool m_aborted = false;
    bool m_waitingForArchive = false;
    bool m_archiveReady = false;       // UploadingBackup seen
    Result m_override;                 // reported instead of the job result
    QString m_remoteDir;
    QString m_archivePath;
    QString m_seenPin;                 // server identity seen by the last connection
    QStringList m_listing;
};

} // namespace NetVfs

#endif
