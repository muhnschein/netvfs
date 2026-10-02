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

// Server identity as exposed to QML; empty map for protocols without one:
// { kind: "ssh"|"tls", algorithm, fingerprint, pin, pinOptions: {host_key[,
// tls_verify_peer]} } and for TLS also { subject, issuer, notBefore,
// notAfter (ISO 8601 UTC), sans, certSha256 ("AB:CD:..."), systemTrusted,
// problems, problemTexts } (SPEC-v2 XA-5, XC-16).
QVariantMap identityToVariant(const NetVfs::ServerIdentity &identity);
// Translated sentences for ServerIdentity::Problem bits, in bit order.
QStringList tlsProblemTexts(int problems);
// "ab12cd" -> "AB:12:CD".
QString colonHex(const QString &hex);

// "SHA256:<unpadded base64>" of a raw key blob, as printed by ssh-keygen -lf.
QString sha256Fingerprint(const QByteArray &publicKeyBlob);

// 0 (protocol default) for an empty or invalid port field.
int parsePort(const QString &port);
// Normalized backups folder ("" if invalid); SMB paths lose a leading '/'
// (SPEC-smb M-8).
QString cleanFolderPath(const QString &provider, const QString &path);

// Input validation for the account dialogs (QML singleton NetVfsInput),
// applied before any connection is made (SPEC-smb M-9). Every *Problem()
// method returns an empty string when the input is acceptable, or a
// translated, specific message. Logic lives here (not in QML) so it is
// unit tested.
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
    // A path on the server such as the WebDAV base path: absolute, no "."
    // or ".." components.
    Q_INVOKABLE QString serverPathProblem(const QString &path) const;
    Q_INVOKABLE QString backupsPathProblem(const QString &provider, const QString &path) const;
    Q_INVOKABLE QString cleanBackupsPath(const QString &provider, const QString &path) const;
};

// Account data, labels and texts for the settings UI (QML singleton
// NetVfsHelpers).
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
    // Whether the accounts framework knows the service (the netvfs-files
    // services are a separate package, SPEC-v2 XP-1).
    Q_INVOKABLE bool isServiceInstalled(const QString &serviceName) const;

    // SPEC-v2 XA-4: whether `params` may be used for "backup" or "files";
    // serviceRefusalText() says why not ("" when allowed).
    Q_INVOKABLE bool serviceAllowed(const QVariantMap &params, const QString &service) const;
    Q_INVOKABLE QString serviceRefusalText(const QVariantMap &params, const QString &service) const;
    // SPEC-v2 XA-7: the account has no secret by design (interactive, smb guest).
    Q_INVOKABLE bool secretOptional(const QVariantMap &params) const;

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

    // Values written when an account is created (SPEC 6.2, 7.3 step 5,
    // SPEC-v2 XA-1). `services`: { backup: bool, files: bool, backupsPath,
    // filesRoot }. Result: { global: {key: value}, services: {<service name>:
    // {key: value}}, enable: [service names], signInService: the service the
    // identity is created for (backup if enabled, else files) }.
    Q_INVOKABLE QVariantMap creationSettings(const QVariantMap &params, const QVariantMap &services) const;
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

    Q_INVOKABLE QString authModeText(const QString &authMode) const;
};

} // namespace NetVfsUi

#endif
