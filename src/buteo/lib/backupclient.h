// SPDX-License-Identifier: LGPL-2.1-or-later
// Structure adapted from the Nextcloud backup plugin of sailfish-account-nextcloud
// (NextcloudBackupOperationClient, Syncer):
//   SPDX-FileCopyrightText: 2019 - 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2019 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#ifndef NETVFS_BUTEO_BACKUPCLIENT_H
#define NETVFS_BUTEO_BACKUPCLIENT_H

#include "networkjob.h"

#include <ClientPlugin.h>
#include <SyncCommonDefs.h>
#include <SyncResults.h>

#include <QtCore/QPointer>

#include <functional>
#include <memory>

namespace Accounts {
class Manager;
}

namespace NetVfs {

class AccountSession;
class BackupService;

// The Buteo client plugin shared by all providers and operations (SPEC 8.1).
// Lives on the plugin thread; network work runs in NetworkJobs (B-3).
class BackupClient : public Buteo::ClientPlugin
{
    Q_OBJECT
    Q_PROPERTY(QString provider READ provider CONSTANT)
    Q_PROPERTY(QString operationName READ operationName CONSTANT)
public:
    enum class Operation { Backup, BackupQuery, BackupRestore };

    // How a run opens its account session; empty means AccountSession::open()
    // (accounts database and signond). Tests pass their own.
    using SessionFactory = std::function<AccountSession *(int accountId, QObject *parent)>;

    BackupClient(const QString &provider, Operation operation, const QString &pluginName,
                 const Buteo::SyncProfile &profile, Buteo::PluginCbInterface *cbInterface,
                 const SessionFactory &sessionFactory = SessionFactory());
    ~BackupClient() override;
    Q_DISABLE_COPY(BackupClient)

    QString provider() const { return m_provider; }
    Operation operation() const { return m_operation; }
    QString operationName() const;

    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus status = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;

    // SPEC 8.7.
    static Buteo::SyncResults::MinorCode minorCodeFor(Error error);
    // What abortSync() reports for the status Buteo passes in (B-4).
    static Buteo::SyncResults::MinorCode minorCodeForAbort(Sync::SyncStatus status);

public Q_SLOTS:
    void connectivityStateChanged(Sync::ConnectivityType type, bool state) override;

private:
    using Continuation = void (BackupClient::*)();

    void shutdown();
    void onSessionReady();
    void onDeviceId(const Result &result, const QString &deviceId);
    void startOperation();
    void startJob(const NetworkJob::Body &body, Continuation next);
    void onJobFinished();

    void requestArchive();
    void onArchiveRequested(const Result &result, const QString &path);
    void onCloudBackupStatusChanged(int accountId, const QString &status);
    void onCloudBackupError(int accountId, const QString &error, const QString &errorString);
    void startUpload();
    void reportBackups();
    void onCloudRestoreStatusChanged(int accountId, const QString &status);
    void onCloudRestoreError(int accountId, const QString &error, const QString &errorString) const;
    void succeed();

    void fail(const Result &result);
    void finish(const Result &result);
    void recordAttention(const Result &result);
    void removeLocalArchive();
    static void removeArchive(const QString &path);
    void report(Buteo::SyncResults::MinorCode code, const QString &message);

    const QString m_provider;
    const Operation m_operation;
    const SessionFactory m_sessionFactory;
    int m_accountId = 0;

    BackupService *m_service = nullptr;
    QPointer<AccountSession> m_session;
    std::unique_ptr<Accounts::Manager> m_manager;
    QPointer<NetworkJob> m_job;
    Continuation m_next = nullptr;

    quint64 m_run = 0;               // changes whenever a run starts or ends
    bool m_running = false;
    bool m_waitingForArchive = false;
    bool m_archiveReady = false;     // UploadingBackup seen
    bool m_aborted = false;
    Buteo::SyncResults::MinorCode m_abortCode = Buteo::SyncResults::ABORTED;
    Result m_override;               // reported instead of the job result (restore canceled)
    QString m_remoteDir;
    QString m_archivePath;
    QString m_seenPin;               // server identity seen by the last connection
    QStringList m_listing;
    Buteo::SyncResults m_results;
};

} // namespace NetVfs

#endif
