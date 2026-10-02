// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backupservice.h"

#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCallWatcher>
#include <QtDBus/QDBusPendingReply>

#include <memory>

namespace NetVfs {

namespace {
const char Service[] = "org.sailfishos.backup";
const char ObjectPath[] = "/sailfishbackup";
const char Interface[] = "org.sailfishos.backup";

Result callError(const QString &method, const QDBusMessage &reply)
{
    return Result(Error::Internal, QStringLiteral("Call to %1() failed: %2 %3")
                                       .arg(method, reply.errorName(), reply.errorMessage()));
}
} // namespace

BackupService::BackupService(const QDBusConnection &connection, QObject *parent)
    : QObject(parent)
    , m_connection(connection)
{
    subscribe("cloudBackupStatusChanged", SLOT(onCloudBackupStatusChanged(int,QString)));
    subscribe("cloudBackupError", SLOT(onCloudBackupError(int,QString,QString)));
    subscribe("cloudRestoreStatusChanged", SLOT(onCloudRestoreStatusChanged(int,QString)));
    subscribe("cloudRestoreError", SLOT(onCloudRestoreError(int,QString,QString)));
}

void BackupService::subscribe(const char *name, const char *slot)
{
    m_connection.connect(QLatin1String(Service), QLatin1String(ObjectPath), QLatin1String(Interface),
                         QLatin1String(name), this, slot);
}

void BackupService::call(const QString &method, const QVariantList &arguments,
                         const std::function<void(const QDBusMessage &)> &done)
{
    QDBusMessage message = QDBusMessage::createMethodCall(QLatin1String(Service), QLatin1String(ObjectPath),
                                                          QLatin1String(Interface), method);
    message.setArguments(arguments);
    auto watcher = std::make_unique<QDBusPendingCallWatcher>(m_connection.asyncCall(message));
    watcher->setParent(this);
    QDBusPendingCallWatcher *raw = watcher.release();   // owned by this service
    connect(raw, &QDBusPendingCallWatcher::finished, this, [raw, done]() {
        done(raw->reply());
        raw->deleteLater();
    });
}

void BackupService::backupFileDeviceId(const StringReply &done)
{
    const QString method = QStringLiteral("backupFileDeviceId");
    call(method, QVariantList(), [method, done](const QDBusMessage &reply) {
        if (reply.type() != QDBusMessage::ReplyMessage)
            done(callError(method, reply), QString());
        else
            done(Result::success(), reply.arguments().value(0).toString());
    });
}

void BackupService::createBackupForSyncProfile(const QString &profileName, const StringReply &done)
{
    const QString method = QStringLiteral("createBackupForSyncProfile");
    call(method, QVariantList() << profileName, [method, done](const QDBusMessage &reply) {
        const QString path = reply.arguments().value(0).toString();
        if (reply.type() != QDBusMessage::ReplyMessage)
            done(callError(method, reply), QString());
        else if (path.isEmpty())
            done(Result(Error::Internal, QStringLiteral("%1() returned no archive path").arg(method)), QString());
        else
            done(Result::success(), path);
    });
}

void BackupService::setCloudBackups(const QString &profileName, const QStringList &files, const VoidReply &done)
{
    const QString method = QStringLiteral("setCloudBackups");
    call(method, QVariantList() << profileName << files, [method, done](const QDBusMessage &reply) {
        if (reply.type() != QDBusMessage::ReplyMessage)
            done(callError(method, reply));
        else
            done(Result::success());
    });
}

void BackupService::onCloudBackupStatusChanged(int accountId, const QString &status)
{
    emit cloudBackupStatusChanged(accountId, status);
}

void BackupService::onCloudBackupError(int accountId, const QString &error, const QString &errorString)
{
    emit cloudBackupError(accountId, error, errorString);
}

void BackupService::onCloudRestoreStatusChanged(int accountId, const QString &status)
{
    emit cloudRestoreStatusChanged(accountId, status);
}

void BackupService::onCloudRestoreError(int accountId, const QString &error, const QString &errorString)
{
    emit cloudRestoreError(accountId, error, errorString);
}

} // namespace NetVfs
