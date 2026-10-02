// SPDX-License-Identifier: LGPL-2.1-or-later
// Structure adapted from the Nextcloud backup plugin of sailfish-account-nextcloud
// (NextcloudBackupOperationClient):
//   SPDX-FileCopyrightText: 2020 Open Mobile Platform LLC
//   SPDX-FileCopyrightText: 2020 - 2023 Jolla Ltd.
//   SPDX-FileCopyrightText: 2024 - 2025 Jolla Mobile Ltd
//   SPDX-License-Identifier: BSD-3-Clause
#ifndef NETVFS_BUTEO_BACKUPCLIENT_H
#define NETVFS_BUTEO_BACKUPCLIENT_H

#include "backuprun.h"

#include <ClientPlugin.h>
#include <SyncCommonDefs.h>
#include <SyncResults.h>

#include <memory>

namespace NetVfs {

class BackupService;

// The Buteo client plugin shared by all providers and operations (SPEC 8.1):
// the Buteo-facing shell. Each startSync() is carried out by a BackupRun.
class BackupClient : public Buteo::ClientPlugin
{
    Q_OBJECT
    Q_PROPERTY(QString provider READ provider CONSTANT)
    Q_PROPERTY(QString operationName READ operationName CONSTANT)
public:
    using Operation = BackupOperation;
    using SessionFactory = NetVfs::SessionFactory;

    // `sessionFactory`: how runs open their account session; empty means
    // AccountSession::open(). Tests pass their own.
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
    bool isRunning() const { return m_run && m_run->isRunning(); }
    void onRunFinished(const Result &result);
    void report(Buteo::SyncResults::MinorCode code, const QString &message);

    const QString m_provider;
    const Operation m_operation;
    const SessionFactory m_sessionFactory;
    int m_accountId = 0;
    std::unique_ptr<BackupService> m_service;
    std::unique_ptr<BackupRun> m_run;     // the current or last run; declared after the service it uses
    bool m_aborted = false;
    Buteo::SyncResults::MinorCode m_abortCode = Buteo::SyncResults::ABORTED;
    Buteo::SyncResults m_results;
};

} // namespace NetVfs

#endif
