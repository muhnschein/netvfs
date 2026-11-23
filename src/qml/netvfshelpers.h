// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_HELPERS_H
#define NETVFS_QML_HELPERS_H

#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

namespace NetVfsUi {
NetVfs::ConnectionParams paramsFromVariant(const QVariantMap &map);
QVariantMap paramsToVariant(const NetVfs::ConnectionParams &params);

QVariantMap identityToVariant(const NetVfs::ServerIdentity &identity);

QString sha256Fingerprint(const QByteArray &publicKeyBlob);

int parsePort(const QString &port);
QString cleanFolderPath(const QString &provider, const QString &path);

class InputRules : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(InputRules)

public:
    explicit InputRules(QObject *parent = nullptr);

    Q_INVOKABLE int defaultPort(const QString &provider) const;
    Q_INVOKABLE QString hostProblem(const QString &host) const;
    Q_INVOKABLE QString portProblem(const QString &port) const;
    Q_INVOKABLE int portValue(const QString &port) const;
    Q_INVOKABLE QString userNameProblem(const QString &userName) const;
    Q_INVOKABLE QString shareProblem(const QString &share) const;
    Q_INVOKABLE QString backupsPathProblem(const QString &provider, const QString &path) const;
    Q_INVOKABLE QString cleanBackupsPath(const QString &provider, const QString &path) const;
};

class Helpers : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Helpers)
    Q_PROPERTY(QString defaultBackupsPath READ defaultBackupsPath CONSTANT)
    Q_PROPERTY(QString credentialsApplication READ credentialsApplication CONSTANT)
    Q_PROPERTY(QString credentialsName READ credentialsName CONSTANT)
    Q_PROPERTY(QString backupsPathKey READ backupsPathKey CONSTANT)
    Q_PROPERTY(QString filesRootKey READ filesRootKey CONSTANT)

public:
    explicit Helpers(QObject *parent = nullptr);

    QString defaultBackupsPath() const;
    QString credentialsApplication() const;
    QString credentialsName() const;
    QString backupsPathKey() const;
    QString filesRootKey() const;

    Q_INVOKABLE QString backupServiceName(const QString &provider) const;
    Q_INVOKABLE QString filesServiceName(const QString &provider) const;
    Q_INVOKABLE bool isProviderInstalled(const QString &provider) const;
    Q_INVOKABLE bool isServiceInstalled(const QString &serviceName) const;

    Q_INVOKABLE bool serviceAllowed(const QVariantMap &params, const QString &service) const;
    Q_INVOKABLE QString serviceRefusalText(const QVariantMap &params, const QString &service) const;
    Q_INVOKABLE bool secretOptional(const QVariantMap &params) const;

    Q_INVOKABLE QString accountLabel(const QString &userName, const QString &host) const;

    Q_INVOKABLE QVariantMap makeParams(const QString &provider, const QString &host, const QString &port,
                                       const QString &userName, const QVariantMap &options) const;
    Q_INVOKABLE QVariantMap withOptions(const QVariantMap &params, const QVariantMap &options) const;
    Q_INVOKABLE QVariantMap paramsFromConfiguration(const QString &provider,
                                                    const QVariantMap &configuration) const;

    Q_INVOKABLE QVariantMap creationSettings(const QVariantMap &params, const QVariantMap &services) const;
    Q_INVOKABLE QVariantMap credentialsLabelSettings(const QVariantMap &params) const;
    Q_INVOKABLE QVariantMap updateSettings(const QVariantMap &params) const;

    Q_INVOKABLE QString attentionState(const QVariantMap &configuration) const;
    Q_INVOKABLE QString attentionText(const QString &state) const;

    Q_INVOKABLE QVariantMap identityFromPin(const QString &pin) const;
    Q_INVOKABLE QString seenPin(const QString &provider, const QVariantMap &configuration) const;

    Q_INVOKABLE QString hostKeyHint(const QString &algorithm) const;

    Q_INVOKABLE QString authModeText(const QString &authMode) const;
};

}
#endif
