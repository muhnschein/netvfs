// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef NETVFS_QML_HELPERS_H
#define NETVFS_QML_HELPERS_H

#include "types.h"

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

namespace NetVfsUi {

// Connection parameters as passed from QML: { provider, host, port, username,
// options: { host_key, auth_mode, share, domain, require_encryption, ... } }.
NetVfs::ConnectionParams paramsFromVariant(const QVariantMap &map);
QVariantMap paramsToVariant(const NetVfs::ConnectionParams &params);

// Server identity as exposed to QML: { algorithm, fingerprint, pin }; empty
// map for protocols without one.
QVariantMap identityToVariant(const NetVfs::ServerIdentity &identity);

// "SHA256:<unpadded base64>" of a raw key blob, as printed by ssh-keygen -lf.
QString sha256Fingerprint(const QByteArray &publicKeyBlob);

// Validation and account data for the settings UI. Every *Problem() method
// returns an empty string when the input is acceptable, or a translated,
// specific message. Logic lives here (not in QML) so it is unit tested.
class Helpers : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Helpers)
    Q_PROPERTY(QString defaultBackupsPath READ defaultBackupsPath CONSTANT)
    Q_PROPERTY(QString credentialsApplication READ credentialsApplication CONSTANT)
    Q_PROPERTY(QString credentialsName READ credentialsName CONSTANT)
    Q_PROPERTY(QString backupsPathKey READ backupsPathKey CONSTANT)

public:
    explicit Helpers(QObject *parent = nullptr);

    QString defaultBackupsPath() const;
    QString credentialsApplication() const;
    QString credentialsName() const;
    QString backupsPathKey() const;

    Q_INVOKABLE int defaultPort(const QString &provider) const;
    Q_INVOKABLE QString backupServiceName(const QString &provider) const;
    Q_INVOKABLE bool isProviderInstalled(const QString &provider) const;

    Q_INVOKABLE QString hostProblem(const QString &host) const;
    Q_INVOKABLE QString portProblem(const QString &port) const;
    // 0 (protocol default) for an empty field.
    Q_INVOKABLE int portValue(const QString &port) const;
    Q_INVOKABLE QString userNameProblem(const QString &userName) const;
    Q_INVOKABLE QString shareProblem(const QString &share) const;
    Q_INVOKABLE QString backupsPathProblem(const QString &provider, const QString &path) const;
    // Normalized folder; SMB paths lose a leading '/' (SPEC-smb M-8).
    Q_INVOKABLE QString cleanBackupsPath(const QString &provider, const QString &path) const;

    // SPEC A-1, A-2: "user@host".
    Q_INVOKABLE QString accountLabel(const QString &userName, const QString &host) const;

    Q_INVOKABLE QVariantMap makeParams(const QString &provider, const QString &host, const QString &port,
                                       const QString &userName, const QVariantMap &options) const;
    // A copy of `params` with `options` merged in; an empty string value
    // removes that option.
    Q_INVOKABLE QVariantMap withOptions(const QVariantMap &params, const QVariantMap &options) const;
    // Rebuilds connection parameters from Account.configurationValues("").
    Q_INVOKABLE QVariantMap paramsFromConfiguration(const QString &provider,
                                                    const QVariantMap &configuration) const;

    // Values written when an account is created (SPEC 6.2, 7.3 step 5):
    // { global: {key: value}, service: {key: value}, serviceName: "<p>-backup" }.
    Q_INVOKABLE QVariantMap creationSettings(const QVariantMap &params, const QString &backupsPath) const;
    // Values written after credentials were created (A-2):
    // { global: { default_credentials_username: "user@host" } }.
    Q_INVOKABLE QVariantMap credentialsLabelSettings(const QVariantMap &params) const;
    // Values written when the update flow (SPEC 7.5) succeeds:
    // { global: {...}, remove: [keys] }. Clears the attention state and, for
    // SFTP, stores the accepted pin and the (possibly new) sign-in method.
    Q_INVOKABLE QVariantMap updateSettings(const QVariantMap &params) const;

    // "auth-failed", "server-identity-changed", "credentials-missing" (device
    // restore: CredentialsNeedUpdate without a netvfs attention value) or "".
    Q_INVOKABLE QString attentionState(const QVariantMap &configuration) const;
    Q_INVOKABLE QString attentionText(const QString &state) const;

    // Identity of a stored pin "<algorithm> <base64>"; empty map if invalid.
    Q_INVOKABLE QVariantMap identityFromPin(const QString &pin) const;
    // The pin recorded together with server-identity-changed (host_key_seen).
    Q_INVOKABLE QString seenPin(const QString &provider, const QVariantMap &configuration) const;

    // SPEC-sftp S-8: where the same fingerprint can be printed on the server.
    Q_INVOKABLE QString hostKeyHint(const QString &algorithm) const;

    // SPEC-smb M-3 labels; SFTP is always encrypted.
    Q_INVOKABLE QString transportSecurityText(const QVariantMap &params) const;
    Q_INVOKABLE QString authModeText(const QString &authMode) const;
};

} // namespace NetVfsUi

#endif
