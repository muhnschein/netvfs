// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_BUTEO_BACKUPSERVICE_H
#define NETVFS_BUTEO_BACKUPSERVICE_H

#include "error.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtDBus/QDBusConnection>

#include <functional>

QT_BEGIN_NAMESPACE
class QDBusMessage;
QT_END_NAMESPACE

namespace NetVfs {

// Client of the platform backup service (SPEC 3.4): session bus,
// org.sailfishos.backup at /sailfishbackup. Calls are asynchronous so the
// plugin thread keeps serving its event loop; each callback runs at most
// once, on the owning thread, and never after the service object is gone.
class BackupService : public QObject
{
    Q_OBJECT
public:
    using StringReply = std::function<void(const Result &, const QString &)>;
    using VoidReply = std::function<void(const Result &)>;

    explicit BackupService(const QDBusConnection &connection = QDBusConnection::sessionBus(),
                           QObject *parent = nullptr);

    void backupFileDeviceId(const StringReply &done);
    void createBackupForSyncProfile(const QString &profileName, const StringReply &done);
    void setCloudBackups(const QString &profileName, const QStringList &files, const VoidReply &done);

Q_SIGNALS:
    void cloudBackupStatusChanged(int accountId, const QString &status);
    void cloudBackupError(int accountId, const QString &error, const QString &errorString);
    void cloudRestoreStatusChanged(int accountId, const QString &status);
    void cloudRestoreError(int accountId, const QString &error, const QString &errorString);

private Q_SLOTS:
    void onCloudBackupStatusChanged(int accountId, const QString &status);
    void onCloudBackupError(int accountId, const QString &error, const QString &errorString);
    void onCloudRestoreStatusChanged(int accountId, const QString &status);
    void onCloudRestoreError(int accountId, const QString &error, const QString &errorString);

private:
    void subscribe(const char *name, const char *slot);
    void call(const QString &method, const QVariantList &arguments,
              const std::function<void(const QDBusMessage &)> &done);

    QDBusConnection m_connection;
};

} // namespace NetVfs

#endif
