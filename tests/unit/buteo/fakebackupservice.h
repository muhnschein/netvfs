// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_TEST_FAKEBACKUPSERVICE_H
#define NETVFS_TEST_FAKEBACKUPSERVICE_H

#include <QtCore/QObject>
#include <QtCore/QPair>
#include <QtCore/QStringList>
#include <QtCore/QTemporaryDir>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusContext>

#include <functional>

// Stand-in for the platform backup service (SPEC 3.4) on its own session bus
// connection: org.sailfishos.backup at /sailfishbackup.
class FakeBackupService : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.backup")
public:
    FakeBackupService();
    ~FakeBackupService() override;
    Q_DISABLE_COPY(FakeBackupService)

    bool registerOnBus();
    void reset();

    // Behaviour
    QString deviceId;
    bool failDeviceId = false;
    bool failCreate = false;
    bool returnEmptyPath = false;
    bool failSetCloudBackups = false;
    int statusBeforeReplyAccount = 0;   // emit UploadingBackup for it before replying
    QByteArray archiveContent;
    std::function<void()> onCreate;      // runs before createBackupForSyncProfile() replies

    // Observations
    QStringList createCalls;
    QStringList serverLogAtCreate;       // FakeServer log when the archive was requested
    QList<QPair<QString, QStringList>> cloudBackups;
    QString lastArchivePath;
    QString archiveRoot() const { return m_dir.path(); }

    void emitBackupStatus(int accountId, const QString &status);
    void emitBackupError(int accountId, const QString &error, const QString &errorString);
    void emitRestoreStatus(int accountId, const QString &status);
    void emitRestoreError(int accountId, const QString &error, const QString &errorString);

public Q_SLOTS:
    QString backupFileDeviceId();
    QString createBackupForSyncProfile(const QString &profileName);
    void setCloudBackups(const QString &profileName, const QStringList &files);

private:
    void send(const QString &signal, const QVariantList &arguments);

    QDBusConnection m_connection;
    QTemporaryDir m_dir;
    int m_archives = 0;
};

#endif
