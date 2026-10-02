// SPDX-License-Identifier: LGPL-2.1-or-later
#include "fakebackupservice.h"
#include "fakebackend.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QMutexLocker>
#include <QtDBus/QDBusMessage>

namespace {
const char Service[] = "org.sailfishos.backup";
const char ObjectPath[] = "/sailfishbackup";
const char Interface[] = "org.sailfishos.backup";
} // namespace

FakeBackupService::FakeBackupService()
    : m_connection(QDBusConnection::connectToBus(QDBusConnection::SessionBus, QStringLiteral("netvfs-fake-backup")))
{
    reset();
}

FakeBackupService::~FakeBackupService()
{
    m_connection.unregisterObject(QLatin1String(ObjectPath));
    m_connection.unregisterService(QLatin1String(Service));
    QDBusConnection::disconnectFromBus(QStringLiteral("netvfs-fake-backup"));
}

bool FakeBackupService::registerOnBus()
{
    return m_connection.isConnected()
            && m_connection.registerObject(QLatin1String(ObjectPath), this, QDBusConnection::ExportAllSlots)
            && m_connection.registerService(QLatin1String(Service));
}

void FakeBackupService::reset()
{
    deviceId = QStringLiteral("device-1");
    failDeviceId = false;
    failCreate = false;
    returnEmptyPath = false;
    failSetCloudBackups = false;
    statusBeforeReplyAccount = 0;
    onCreate = nullptr;
    archiveContent = QByteArray(300 * 1024, 'a');
    createCalls.clear();
    serverLogAtCreate.clear();
    cloudBackups.clear();
    lastArchivePath.clear();
}

QString FakeBackupService::backupFileDeviceId()
{
    if (failDeviceId)
        sendErrorReply(QDBusError::Failed, QStringLiteral("no device id"));
    return deviceId;
}

QString FakeBackupService::createBackupForSyncProfile(const QString &profileName)
{
    createCalls << profileName;
    {
        NetVfs::Test::FakeServer *server = NetVfs::Test::FakeServer::instance();
        QMutexLocker lock(&server->mutex);
        serverLogAtCreate = server->log;
    }
    if (failCreate) {
        sendErrorReply(QDBusError::Failed, QStringLiteral("cannot create"));
        return QString();
    }
    if (returnEmptyPath)
        return QString();

    // Like the platform: the archive in a directory of its own.
    ++m_archives;
    const QString dir = m_dir.path() + QStringLiteral("/run-%1").arg(m_archives);
    QDir().mkpath(dir);
    lastArchivePath = dir + QStringLiteral("/sailfish_backup_%1.tar").arg(m_archives);
    QFile file(lastArchivePath);
    if (file.open(QIODevice::WriteOnly))
        file.write(archiveContent);
    file.close();
    if (statusBeforeReplyAccount)
        emitBackupStatus(statusBeforeReplyAccount, QStringLiteral("UploadingBackup"));
    if (onCreate)
        onCreate();
    return lastArchivePath;
}

void FakeBackupService::setCloudBackups(const QString &profileName, const QStringList &files)
{
    if (failSetCloudBackups) {
        sendErrorReply(QDBusError::AccessDenied, QStringLiteral("refused"));
        return;
    }
    cloudBackups.append(qMakePair(profileName, files));
}

void FakeBackupService::send(const QString &signal, const QVariantList &arguments)
{
    QDBusMessage message = QDBusMessage::createSignal(QLatin1String(ObjectPath), QLatin1String(Interface), signal);
    message.setArguments(arguments);
    m_connection.send(message);
}

void FakeBackupService::emitBackupStatus(int accountId, const QString &status)
{
    send(QStringLiteral("cloudBackupStatusChanged"), QVariantList() << accountId << status);
}

void FakeBackupService::emitBackupError(int accountId, const QString &error, const QString &errorString)
{
    send(QStringLiteral("cloudBackupError"), QVariantList() << accountId << error << errorString);
}

void FakeBackupService::emitRestoreStatus(int accountId, const QString &status)
{
    send(QStringLiteral("cloudRestoreStatusChanged"), QVariantList() << accountId << status);
}

void FakeBackupService::emitRestoreError(int accountId, const QString &error, const QString &errorString)
{
    send(QStringLiteral("cloudRestoreError"), QVariantList() << accountId << error << errorString);
}
